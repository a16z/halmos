import json
import subprocess
from dataclasses import dataclass
from typing import Any

import pytest
from z3 import (
    Array,
    BitVec,
    BitVecSort,
    BitVecVal,
    SolverFor,
    is_bv,
)

import halmos.sevm
from halmos.__main__ import mk_block, render_trace
from halmos.bytevec import ByteVec
from halmos.exceptions import MessageDepthLimitError, Revert, WriteInStaticContext
from halmos.sevm import (
    SEVM,
    ZERO,
    CallContext,
    Contract,
    EventLog,
    Exec,
    Message,
    NotConcreteError,
    Path,
    byte_length,
    con,
    int_of,
)
from halmos.utils import EVM

# keccak256("FooEvent()")
FOO_EVENT_SIG = 0x34E21A9428B1B47E73C4E509EABEEA7F2B74BECA07D82AAC87D4DD28B74C2A4A

# keccak256("Log(uint256)")
LOG_U256_SIG = 0x909C57D5C6AC08245CF2A6DE3900E2B868513FA59099B92B27D8DB823D92DF9C

# bytes4(keccak256("Panic(uint256)")) + bytes32(1)
PANIC_1 = 0x4E487B710000000000000000000000000000000000000000000000000000000000000001

DEFAULT_EMPTY_CONSTRUCTOR = """
contract Foo {}
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

# go()
go_selector = bytes.fromhex("0f59f83a")

# go(uint256)
go_uint256_selector = BitVecVal(0xB20E7344, 32)

p_x_uint256 = BitVec("p_x_uint256", 256)

default_calldata = ByteVec(go_selector)
go_uint256_calldata = ByteVec([go_uint256_selector, p_x_uint256])


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


@dataclass(frozen=True)
class SingleResult:
    is_single: bool
    value: Any | None

    # allows tuple-like unpacking
    def __iter__(self):
        return iter((self.is_single, self.value))


NO_SINGLE_RESULT = SingleResult(False, None)


def single(iterable) -> SingleResult:
    """
    Returns (True, element) if the iterable has exactly one element
    or (False, None) otherwise.

    Note:
        - if the iterable has a single None element, this returns (True, None)
    """
    iterator = iter(iterable)
    element = None
    try:
        element = next(iterator)
    except StopIteration:
        return NO_SINGLE_RESULT

    try:
        next(iterator)
        return NO_SINGLE_RESULT
    except StopIteration:
        return SingleResult(True, element)


def is_single(iterable) -> bool:
    """
    Returns True if the iterable has exactly one element, False otherwise.
    """

    return single(iterable).is_single


def empty(iterable) -> bool:
    """
    Returns True if the iterable is empty, False otherwise.
    """
    iterator = iter(iterable)
    try:
        next(iterator)
        return False
    except StopIteration:
        return True


def mk_create_ex(
    hexcode, sevm, solver, caller=caller, value=0, this=this, storage=None
) -> Exec:
    if storage is None:
        storage = {}
    bytecode = Contract.from_hexcode(hexcode)
    storage[this] = {}

    message = Message(
        target=this,
        caller=caller,
        value=value,
        data=ByteVec(),
        call_scheme=EVM.CREATE,
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
        path=Path(solver),
    )


def mk_ex(
    hexcode,
    sevm,
    solver,
    caller=caller,
    value=ZERO,
    this=this,
    storage=None,
    data=default_calldata,
) -> Exec:
    if storage is None:
        storage = {}
    bytecode = Contract.from_hexcode(hexcode)
    storage[this] = {}

    message = Message(
        target=this,
        caller=caller,
        value=value,
        data=data,
        call_scheme=EVM.CALL,
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
        path=Path(solver),
    )


BuildOutput = dict


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


def find_contract(contract_name: str, build_output: BuildOutput) -> dict:
    for name in build_output["contracts"]:
        if name.endswith(f":{contract_name}"):
            return build_output["contracts"][name]

    raise Exception(f"Contract {contract_name} not found in {build_output}")


def get_bytecode(source: str, contract_name: str = "Foo"):
    build_output = compile(source)
    contract_object = find_contract(contract_name, build_output)
    return contract_object["bin"], contract_object["bin-runtime"]


def test_deploy_basic(sevm, solver):
    deploy_hexcode, runtime_hexcode = get_bytecode(DEFAULT_EMPTY_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver)

    # before execution
    assert exec.context.output.data is None

    _ = next(sevm.run(exec))
    render_trace(exec.context)

    # after execution
    assert exec.context.output.error is None
    assert exec.context.output.data.unwrap() == bytes.fromhex(runtime_hexcode)
    assert len(exec.context.trace) == 0


def test_deploy_nonpayable_reverts(sevm, solver):
    deploy_hexcode, _ = get_bytecode(DEFAULT_EMPTY_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    _ = next(sevm.run(exec))
    render_trace(exec.context)

    assert isinstance(exec.context.output.error, Revert)
    assert not exec.context.output.data
    assert len(exec.context.trace) == 0


def test_deploy_payable(sevm, solver):
    deploy_hexcode, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                constructor() payable {}
            }
        """
    )
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    _ = next(sevm.run(exec))
    render_trace(exec.context)

    assert exec.context.output.error is None
    assert exec.context.output.data.unwrap() == bytes.fromhex(runtime_hexcode)
    assert len(exec.context.trace) == 0


def test_deploy_event_in_constructor(sevm, solver):
    deploy_hexcode, _ = get_bytecode(
        """
            contract Foo {
                event FooEvent();

                constructor() {
                    emit FooEvent();
                }
            }
        """
    )
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver)

    _ = next(sevm.run(exec))
    render_trace(exec.context)

    assert exec.context.output.error is None
    assert len(exec.context.trace) == 1

    event: EventLog = exec.context.trace[0]
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == FOO_EVENT_SIG
    assert not event.data


def test_simple_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                function view_func() public pure returns (uint) {
                    return 42;
                }

                function go() public view returns (bool success) {
                    (success, ) = address(this).staticcall(abi.encodeWithSignature("view_func()"));
                }
            }
        """
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    render_trace(output_exec.context)

    assert output_exec.context.output is not None
    assert output_exec.context.output.error is None

    # go() returns success=true
    assert int_of(output_exec.context.output.data) == 1

    # view_func() returns 42
    (is_single_call, subcall) = single(output_exec.context.subcalls())
    assert is_single_call
    assert subcall.output.error is None
    assert int_of(subcall.output.data) == 42


def test_failed_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                function just_fails() public pure returns (uint) {
                    assert(false);
                }

                function go() public view returns (bool success) {
                    (success, ) = address(this).staticcall(abi.encodeWithSignature("just_fails()"));
                }
            }
        """
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    render_trace(output_exec.context)

    # go() does not revert, it returns success=false
    assert output_exec.context.output.error is None
    assert int_of(output_exec.context.output.data) == 0

    # the just_fails() subcall fails
    (is_single_call, subcall) = single(output_exec.context.subcalls())
    assert is_single_call
    assert isinstance(subcall.output.error, Revert)
    assert int_of(subcall.output.data) == PANIC_1


def test_failed_static_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
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
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    render_trace(output_exec.context)

    # go() does not revert, it returns success=false
    assert output_exec.context.output.error is None
    assert int_of(output_exec.context.output.data) == 0

    # the do_sstore() subcall fails
    (is_single_call, subcall) = single(output_exec.context.subcalls())
    assert is_single_call
    assert subcall.message.is_static is True
    assert isinstance(subcall.output.error, WriteInStaticContext)


def test_symbolic_subcall(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                function may_fail(uint256 x) public pure returns (uint) {
                    assert(x != 42);
                }

                function go(uint256 x) public view returns (bool success) {
                    (success, ) = address(this).staticcall(abi.encodeWithSignature("may_fail(uint256)", x));
                }
            }
        """
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = list(sevm.run(input_exec))

    # we get 2 executions, one for x == 42 and one for x != 42
    assert len(execs) == 2
    render_trace(execs[0].context)
    render_trace(execs[1].context)

    # all executions have exactly one subcall and the outer call does not revert
    assert all(is_single(x.context.subcalls()) for x in execs)
    assert all(x.context.output.error is None for x in execs)

    # in one of the executions, the subcall succeeds
    subcalls = list(single(x.context.subcalls()).value for x in execs)
    assert any(subcall.output.error is None for subcall in subcalls)

    # in one of the executions, the subcall reverts
    assert any(isinstance(subcall.output.error, Revert) for subcall in subcalls)


def test_symbolic_create(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
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
    )
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)

    execs = list(sevm.run(input_exec))

    # we get 2 executions, one for x == 42 and one for x != 42
    assert len(execs) == 2
    render_trace(execs[0].context)
    render_trace(execs[1].context)

    # all executions have exactly one subcall and the outer call does not revert
    assert all(is_single(x.context.subcalls()) for x in execs)
    assert all(x.context.output.error is None for x in execs)

    # in one of the executions, the subcall succeeds
    subcalls = list(single(x.context.subcalls()).value for x in execs)
    assert any(subcall.output.error is None for subcall in subcalls)

    # in one of the executions, the subcall reverts
    assert any(isinstance(subcall.output.error, Revert) for subcall in subcalls)


def test_failed_create(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_CREATE)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    render_trace(output_exec.context)

    # go() does not revert, it returns success=false
    assert output_exec.context.output.error is None
    assert int_of(output_exec.context.output.data) == 0

    # the create() subcall fails
    (is_single_call, subcall) = single(output_exec.context.subcalls())
    assert is_single_call
    assert isinstance(subcall.output.error, Revert)
    assert int_of(subcall.output.data) == PANIC_1


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
    execs = list(sevm.run(input_exec))

    for e in execs:
        render_trace(e.context)

    assert len(execs) == 2

    # all executions have a single subcall
    assert all(is_single(x.context.subcalls()) for x in execs)

    all_subcalls = list(single(x.context.subcalls()).value for x in execs)

    # one execution has a single subcall that reverts
    assert any(
        isinstance(subcall.output.error, WriteInStaticContext)
        for subcall in all_subcalls
    )

    # one execution has a single subcall that succeeds and emits an event
    assert any(
        single(x.context.subcalls()).value.output.error is None
        and is_single(x.context.logs())
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
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    (is_single_event, event) = single(output_exec.context.logs())
    assert is_single_event
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == LOG_U256_SIG
    assert event.data.unwrap() == p_x_uint256


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
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    (is_single_event, event) = single(output_exec.context.logs())
    assert is_single_event
    assert len(event.topics) == 2
    assert int_of(event.topics[0]) == LOG_U256_SIG
    assert is_bv(event.topics[1]) and event.topics[1].decl().name() == "p_x_uint256"
    assert not event.data


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
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    top_level_call = output_exec.context
    render_trace(top_level_call)

    assert len(list(top_level_call.subcalls())) == 2
    call1, call2 = tuple(top_level_call.subcalls())

    (is_single_event, event) = single(top_level_call.logs())
    assert is_single_event

    # the trace must preserve the ordering
    assert top_level_call.trace == [call1, event, call2]
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
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    top_level_call = output_exec.context
    render_trace(top_level_call)

    (is_single_call, outer_call) = single(top_level_call.subcalls())
    assert is_single_call

    assert outer_call.message.call_scheme == EVM.STATICCALL
    assert outer_call.message.is_static is True
    assert outer_call.output.error is None

    assert len(list(outer_call.subcalls())) == 1
    inner_call = next(outer_call.subcalls())

    assert inner_call.message.call_scheme == EVM.CALL
    assert inner_call.message.is_static is True
    assert isinstance(inner_call.output.error, WriteInStaticContext)
    assert next(inner_call.logs(), None) is None


def test_halmos_exception_halts_path(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
        contract Foo {
            function sload(uint256 x) public view returns (uint256 value) {
                assembly {
                    value := sload(x)
                }
            }

            function go(uint256 x) public view {
                this.sload(x);
            }
        }
    """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    outer_call = output_exec.context
    render_trace(outer_call)

    # outer call does not return because of NotConcreteError
    assert outer_call.output.error is None
    assert outer_call.output.return_scheme is None

    (is_single_call, inner_call) = single(outer_call.subcalls())
    assert is_single_call

    assert inner_call.message.call_scheme == EVM.STATICCALL
    assert isinstance(inner_call.output.error, NotConcreteError)
    assert not inner_call.output.data
    assert inner_call.output.return_scheme == EVM.SLOAD


def test_deploy_symbolic_bytecode(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                function go(uint256 x) public {
                    assembly {
                        mstore(0, x)
                        let addr := create(0, 0, 32)
                    }
                }
            }
        """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=go_uint256_calldata)
    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    outer_call = output_exec.context
    render_trace(outer_call)

    # outer call does not return because of NotConcreteError
    assert outer_call.output.error is None
    assert outer_call.output.return_scheme is None

    (is_single_call, inner_call) = single(outer_call.subcalls())
    assert is_single_call
    assert inner_call.message.call_scheme == EVM.CREATE

    assert isinstance(inner_call.output.error, NotConcreteError)
    assert not inner_call.output.data
    assert is_bv(inner_call.output.return_scheme)


def test_deploy_empty_runtime_bytecode(sevm: SEVM, solver):
    for creation_bytecode_len in (0, 1):
        _, runtime_hexcode = get_bytecode(
            f"""
                contract Foo {{
                    function go() public {{
                        assembly {{
                            let addr := create(0, 0, {creation_bytecode_len})
                        }}
                    }}
                }}
            """
        )

        input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=default_calldata)
        (is_single_exec, output_exec) = single(sevm.run(input_exec))
        assert is_single_exec

        outer_call = output_exec.context
        render_trace(outer_call)

        (is_single_call, inner_call) = single(outer_call.subcalls())
        assert is_single_call
        assert inner_call.message.call_scheme == EVM.CREATE
        assert len(inner_call.message.data) == creation_bytecode_len

        assert inner_call.output.error is None
        assert len(inner_call.output.data) == 0
        assert inner_call.output.return_scheme == EVM.STOP


def test_call_limit_with_create(monkeypatch, sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(
        """
            contract Foo {
                function go() public {
                    // bytecode for:
                    //     codecopy(0, 0, codesize())
                    //     create(0, 0, codesize())
                    bytes memory creationCode = hex"386000803938600080f050";
                    assembly {
                        let addr := create(0, add(creationCode, 0x20), mload(creationCode))
                    }
                }
            }
        """
    )

    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver, data=default_calldata)

    # override the call depth limit to 3 (the test runs faster)
    MAX_CALL_DEPTH_OVERRIDE = 3
    monkeypatch.setattr(halmos.sevm, "MAX_CALL_DEPTH", MAX_CALL_DEPTH_OVERRIDE)

    (is_single_exec, output_exec) = single(sevm.run(input_exec))
    assert is_single_exec

    outer_call = output_exec.context
    render_trace(outer_call)

    assert not outer_call.output.error
    assert not outer_call.output.data
    assert not outer_call.is_stuck()

    # peel the layer of the call stack onion until we get to the innermost call
    inner_call = outer_call
    for _ in range(MAX_CALL_DEPTH_OVERRIDE):
        (is_single_call, inner_call) = single(inner_call.subcalls())
        assert is_single_call
        assert inner_call.message.call_scheme == EVM.CREATE
        assert byte_length(inner_call.output.data) == 0

    assert isinstance(inner_call.output.error, MessageDepthLimitError)
