import json
import pytest
import subprocess

from typing import Dict, List

from z3 import *

from halmos.__main__ import mk_block, render_trace
from halmos.exceptions import *
from halmos.sevm import (
    Exec,
    Contract,
    Message,
    CallContext,
    CallOutput,
    EventLog,
    con,
    int_of,
    wstore,
    SEVM,
)
from halmos.utils import EVM
from test_fixtures import args, options, sevm

# keccak256("FooEvent()")
FOO_EVENT_SIG = 0x34E21A9428B1B47E73C4E509EABEEA7F2B74BECA07D82AAC87D4DD28B74C2A4A

# keccak256("Log(uint256)")
LOG_U256_SIG = 0x909C57D5C6AC08245CF2A6DE3900E2B868513FA59099B92B27D8DB823D92DF9C

# bytes4(keccak256("Panic(uint256)")) + bytes32(1)
PANIC_1 = 0x4E487B710000000000000000000000000000000000000000000000000000000000000001

DEFAULT_EMPTY_CONSTRUCTOR = """
contract Foo {}
"""

PAYABLE_CONSTRUCTOR = """
contract Foo {
    constructor() payable {}
}
"""

CONSTRUCTOR_EMPTY_EVENT = """
contract Foo {
    event FooEvent();

    constructor() {
        emit FooEvent();
    }
}
"""

SIMPLE_CALL = """
contract Foo {
    function view_func() public pure returns (uint) {
        return 42;
    }

    function go() public view returns (bool success) {
        (success, ) = address(this).staticcall(abi.encodeWithSignature("view_func()"));
    }
}
"""

FAILED_SIMPLE_CALL = """
contract Foo {
    function just_fails() public pure returns (uint) {
        assert(false);
    }

    function go() public view returns (bool success) {
        (success, ) = address(this).staticcall(abi.encodeWithSignature("just_fails()"));
    }
}
"""

FAILED_STATIC_CALL = """
contract Foo {
    uint256 x;

    function do_sstore() public returns (uint) {
        unchecked {
            x += 1;
        }
    }

    function go() public view returns (bool success) {
        (success, ) = address(this).staticcall(abi.encodeWithSignature("do_sstore()"));
    }
}
"""

SYMBOLIC_SUBCALL = """
contract Foo {
    function may_fail(uint256 x) public pure returns (uint) {
        assert(x != 42);
    }

    function go(uint256 x) public view returns (bool success) {
        (success, ) = address(this).staticcall(abi.encodeWithSignature("may_fail(uint256)", x));
    }
}
"""

SYMBOLIC_CREATE = """
contract Bar {
    uint256 immutable x;

    constructor(uint256 _x) {
        assert(_x != 42);
        x = _x;
    }
}

contract Foo {
    function go(uint256 x) public returns (bool success) {
        try new Bar(x) {
            success = true;
        } catch {
            success = false;
        }
    }
}
"""

FAILED_CREATE = """
contract Bar {
    uint256 immutable x;

    constructor(uint256 _x) {
        assert(_x != 42);
        x = _x;
    }
}

contract Foo {
    function go() public returns(bool success) {
        bytes memory creationCode = abi.encodePacked(
            type(Bar).creationCode,
            uint256(42)
        );

        address addr;
        bytes memory returndata;

        assembly {
            addr := create(0, add(creationCode, 0x20), mload(creationCode))

            // advance free mem pointer to allocate `size` bytes
            let free_mem_ptr := mload(0x40)
            mstore(0x40, add(free_mem_ptr, returndatasize()))

            returndata := free_mem_ptr
            mstore(returndata, returndatasize())

            let offset := add(returndata, 32)
            returndatacopy(
                offset,
                0, // returndata offset
                returndatasize()
            )
        }

        success = (addr != address(0));
        // assert(returndata.length == 36);
    }
}
"""


caller = BitVec("msg_sender", 160)
this = BitVec("this_address", 160)
balance = Array("balance_0", BitVecSort(160), BitVecSort(256))

# 0x0f59f83a is keccak256("go()")
default_calldata = list(con(x, size_bits=8) for x in bytes.fromhex("0f59f83a"))

go_uint256_selector = BitVecVal(0xB20E7344, 32)  # keccak256("go(uint256)")
p_x_uint256 = BitVec("p_x_uint256", 256)
go_uint256_calldata: List[BitVecRef] = []
wstore(go_uint256_calldata, 0, 4, go_uint256_selector)
wstore(go_uint256_calldata, 4, 32, p_x_uint256)


@pytest.fixture
def solver(args):
    solver = SolverFor(
        "QF_AUFBV"
    )  # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver.set(timeout=args.solver_timeout_branching)
    return solver


@pytest.fixture
def storage():
    return {}


def render_path(ex: Exec) -> None:
    path = list(dict.fromkeys(ex.path))
    path.remove("True")
    print(f"Path: {', '.join(path)}")


def mk_create_ex(
    hexcode, sevm, solver, caller=caller, value=con(0), this=this, storage={}
) -> Exec:
    bytecode = Contract(hexcode)
    storage[this] = {}

    message = Message(
        target=this,
        caller=caller,
        value=value,
        data=[],
        is_static=False,
    )

    return sevm.mk_exec(
        code={},
        storage=storage,
        balance=balance,
        block=mk_block(),
        context=CallContext(message=message),
        this=this,
        pgm=bytecode,
        symbolic=True,
        solver=solver,
    )


def mk_ex(
    hexcode,
    sevm,
    solver,
    caller=caller,
    value=con(0),
    this=this,
    storage={},
    data=default_calldata,
) -> Exec:
    bytecode = Contract(hexcode)
    storage[this] = {}

    message = Message(
        target=this,
        caller=caller,
        value=value,
        data=data,
        is_static=False,
    )

    return sevm.mk_exec(
        code={this: bytecode},
        storage=storage,
        balance=balance,
        block=mk_block(),
        context=CallContext(message=message),
        this=this,
        pgm=bytecode,
        symbolic=True,
        solver=solver,
    )


BuildOutput = Dict


def compile(source: str) -> BuildOutput:
    proc = subprocess.Popen(
        ["solc", "--combined-json", "bin,bin-runtime", "--no-cbor-metadata", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (stdout, stderr) = proc.communicate(input=source.encode("utf-8"))
    if proc.returncode != 0:
        raise Exception("solc failed: " + stderr.decode("utf-8"))
    return json.loads(stdout)


def find_contract(contract_name: str, build_output: BuildOutput) -> Dict:
    for name in build_output["contracts"]:
        if name.endswith(f":{contract_name}"):
            return build_output["contracts"][name]

    raise Exception(f"Contract {contract_name} not found in {build_output}")


def get_bytecode(source: str, contract_name: str = "Foo"):
    build_output = compile(source)
    contract_object = find_contract("Foo", build_output)
    return contract_object["bin"], contract_object["bin-runtime"]


def test_deploy_basic(sevm, solver):
    deploy_hexcode, runtime_hexcode = get_bytecode(DEFAULT_EMPTY_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver)

    # before execution
    assert exec.context.output.data is None

    sevm.run(exec)
    render_trace(exec.context)

    # after execution
    assert exec.context.output.error is None
    assert exec.context.output.data == bytes.fromhex(runtime_hexcode)
    assert len(exec.context.trace) == 0


def test_deploy_nonpayable_reverts(sevm, solver):
    deploy_hexcode, _ = get_bytecode(DEFAULT_EMPTY_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    sevm.run(exec)
    render_trace(exec.context)

    assert isinstance(exec.context.output.error, Revert)
    assert exec.context.output.data is None
    assert len(exec.context.trace) == 0


def test_deploy_payable(sevm, solver):
    deploy_hexcode, runtime_hexcode = get_bytecode(PAYABLE_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    sevm.run(exec)
    render_trace(exec.context)

    assert exec.context.output.error is None
    assert exec.context.output.data == bytes.fromhex(runtime_hexcode)
    assert len(exec.context.trace) == 0


def test_deploy_event_in_constructor(sevm, solver):
    deploy_hexcode, _ = get_bytecode(CONSTRUCTOR_EMPTY_EVENT)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver)

    sevm.run(exec)
    render_trace(exec.context)

    assert exec.context.output.error is None
    assert len(exec.context.trace) == 1

    event: EventLog = exec.context.trace[0]
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == FOO_EVENT_SIG
    assert event.data is None


def test_simple_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(SIMPLE_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.context)

    assert exec.context.output is not None
    assert exec.context.output.error is None

    # go() returns success=true
    assert int_of(exec.context.output.data) == 1

    # view_func() returns 42
    subcalls = exec.context.subcalls()
    assert len(subcalls) == 1
    assert subcalls[0].output.error is None
    assert int_of(subcalls[0].output.data) == 42


def test_failed_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_SIMPLE_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.context)

    # go() does not revert, it returns success=false
    assert exec.context.output.error is None
    assert int_of(exec.context.output.data) == 0

    # the just_fails() subcall fails
    subcalls = exec.context.subcalls()
    assert len(subcalls) == 1
    assert isinstance(subcalls[0].output.error, Revert)
    assert int_of(subcalls[0].output.data) == PANIC_1


def test_failed_static_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_STATIC_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.context)

    # go() does not revert, it returns success=false
    assert exec.context.output.error is None
    assert int_of(exec.context.output.data) == 0

    # the do_sstore() subcall fails
    subcalls = exec.context.subcalls()
    assert len(subcalls) == 1
    assert subcalls[0].message.is_static is True
    assert isinstance(subcalls[0].output.error, WriteInStaticContext)


def test_symbolic_subcall(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(SYMBOLIC_SUBCALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = sevm.run(input_exec)[0]

    # we get 2 executions, one for x == 42 and one for x != 42
    assert len(execs) == 2
    render_trace(execs[0].context)
    render_trace(execs[1].context)

    # all executions have exactly one subcall and the outer call does not revert
    assert all(len(x.context.subcalls()) == 1 for x in execs)
    assert all(x.context.output.error is None for x in execs)

    # in one of the executions, the subcall succeeds
    assert any(x.context.subcalls()[0].output.error is None for x in execs)

    # in one of the executions, the subcall reverts
    assert any(isinstance(x.context.subcalls()[0].output.error, Revert) for x in execs)


def test_symbolic_create(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(SYMBOLIC_CREATE)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = sevm.run(input_exec)[0]

    # we get 2 executions, one for x == 42 and one for x != 42
    assert len(execs) == 2
    render_trace(execs[0].context)
    render_trace(execs[1].context)

    # all executions have exactly one subcall and the outer call does not revert
    assert all(len(x.context.subcalls()) == 1 for x in execs)
    assert all(x.context.output.error is None for x in execs)

    # in one of the executions, the subcall succeeds
    assert any(x.context.subcalls()[0].output.error is None for x in execs)

    # in one of the executions, the subcall reverts
    assert any(isinstance(x.context.subcalls()[0].output.error, Revert) for x in execs)


def test_failed_create(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_CREATE)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]

    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.context)

    # go() does not revert, it returns success=false
    assert exec.context.output.error is None
    assert int_of(exec.context.output.data) == 0

    # the create() subcall fails
    subcalls = exec.context.subcalls()
    assert len(subcalls) == 1
    assert isinstance(subcalls[0].output.error, Revert)
    assert int_of(subcalls[0].output.data) == PANIC_1


def test_event_conditional_on_symbol(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
        contract Foo {
            event Log(uint256 x);

            function may_log(uint256 x) public returns (uint) {
                if (x == 42) {
                    emit Log(x);
                }
            }

            function go(uint256 x) public returns (bool success) {
                (success, ) = address(this).staticcall(abi.encodeWithSignature("may_log(uint256)", x));
                if (x != 42) {
                    emit Log(x);
                }
            }
        }
    """
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = sevm.run(input_exec)[0]

    for e in execs:
        render_path(e)
        render_trace(e.context)

    assert len(execs) == 2

    # all executions have a single subcall
    assert all(len(x.context.subcalls()) == 1 for x in execs)

    # one execution has a single subcall that reverts
    assert any(
        isinstance(x.context.subcalls()[0].output.error, WriteInStaticContext)
        for x in execs
    )

    # one execution has a single subcall that succeeds and emits an event
    assert any(
        x.context.subcalls()[0].output.error is None and len(x.context.logs()) == 1
        for x in execs
    )


def test_symbolic_event_data(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
        contract Foo {
            event Log(uint256 x);

            function go(uint256 x) public returns (bool success) {
                emit Log(x);
            }
        }
    """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)
    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    output_exec = execs.pop()
    events = output_exec.context.logs()
    assert len(events) == 1

    event = events[0]
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == LOG_U256_SIG
    assert is_bv(event.data) and event.data.decl().name() == "p_x_uint256"


def test_symbolic_event_topic(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
        contract Foo {
            event Log(uint256 indexed x);

            function go(uint256 x) public returns (bool success) {
                emit Log(x);
            }
        }
    """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)
    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    output_exec = execs.pop()
    events = output_exec.context.logs()
    assert len(events) == 1

    event = events[0]
    assert len(event.topics) == 2
    assert int_of(event.topics[0]) == LOG_U256_SIG
    assert is_bv(event.topics[1]) and event.topics[1].decl().name() == "p_x_uint256"
    assert event.data is None


def test_trace_ordering(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
        contract Foo {
            event FooEvent();

            function view_func1() public view returns (uint) {
                return gasleft();
            }

            function view_func2() public view returns (uint) {
                return 42;
            }

            function go(uint256 x) public returns (bool success) {
                (bool succ1, ) = address(this).staticcall(abi.encodeWithSignature("view_func1()"));
                emit FooEvent();
                (bool succ2, ) = address(this).staticcall(abi.encodeWithSignature("view_func2()"));
                success = succ1 && succ2;
            }
        }
        """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)
    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    output_exec = execs.pop()
    render_trace(output_exec.context)

    assert len(output_exec.context.subcalls()) == 2
    assert len(output_exec.context.logs()) == 1

    call1, call2 = tuple(output_exec.context.subcalls())
    event = output_exec.context.logs()[0]

    # the trace must preserve the ordering
    assert output_exec.context.trace == [call1, event, call2]
    assert int_of(call2.output.data) == 42


def test_static_context_propagates(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                event FooEvent();

                function logFoo() public returns (uint) {
                    emit FooEvent();
                    return 42;
                }

                function view_func() public returns (bool succ) {
                    (succ, ) = address(this).call(abi.encodeWithSignature("logFoo()"));
                }

                function go(uint256 x) public view {
                    (bool outerSucc, bytes memory ret) = address(this).staticcall(abi.encodeWithSignature("view_func()"));
                    assert(outerSucc);

                    bool innerSucc = abi.decode(ret, (bool));
                    assert(!innerSucc);
                }
            }
        """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    output_exec = execs.pop()
    render_trace(output_exec.context)

    assert len(output_exec.context.subcalls()) == 1
    outer_call = output_exec.context.subcalls()[0]

    assert outer_call.message.call_scheme == EVM.STATICCALL
    assert outer_call.message.is_static is True
    assert outer_call.output.error is None

    assert len(outer_call.subcalls()) == 1
    inner_call = outer_call.subcalls()[0]

    assert inner_call.message.call_scheme == EVM.CALL
    assert inner_call.message.is_static is True
    assert isinstance(inner_call.output.error, WriteInStaticContext)
    assert len(inner_call.logs()) == 0
