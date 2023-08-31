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
    CallFrame,
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


# TODO: chain calls and events, check ordering
# TODO: symbolic subcalls

caller = BitVec("msg_sender", 160)
this = BitVec("this_address", 160)
balance = Array("balance_0", BitVecSort(160), BitVecSort(256))

# 0x0f59f83a is keccak256("go()")
default_calldata = list(con(x, size_bits=8) for x in bytes.fromhex("0f59f83a"))

go_uint256_selector = BitVecVal(0xB20E7344, 32)  # keccak256("go(uint256)")
p_x_uint256 = BitVec("p_x_uint256", 256)
symbolic_uint256_calldata: List[BitVecRef] = []
wstore(symbolic_uint256_calldata, 0, 4, go_uint256_selector)
wstore(symbolic_uint256_calldata, 4, 32, p_x_uint256)


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
        call_frame=CallFrame(message=message),
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
        call_frame=CallFrame(message=message),
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
    assert exec.call_frame.output is None

    sevm.run(exec)
    render_trace(exec.call_frame)

    # after execution
    assert exec.call_frame.output.error is None
    assert exec.call_frame.output.data == bytes.fromhex(runtime_hexcode)
    assert len(exec.call_frame.trace) == 0


def test_deploy_nonpayable_reverts(sevm, solver):
    deploy_hexcode, _ = get_bytecode(DEFAULT_EMPTY_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    sevm.run(exec)
    render_trace(exec.call_frame)

    assert exec.call_frame.output.error is Revert
    assert exec.call_frame.output.data is None
    assert len(exec.call_frame.trace) == 0


def test_deploy_payable(sevm, solver):
    deploy_hexcode, runtime_hexcode = get_bytecode(PAYABLE_CONSTRUCTOR)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(1))

    sevm.run(exec)
    render_trace(exec.call_frame)

    assert exec.call_frame.output.error is None
    assert exec.call_frame.output.data == bytes.fromhex(runtime_hexcode)
    assert len(exec.call_frame.trace) == 0


def test_deploy_event_in_constructor(sevm, solver):
    deploy_hexcode, _ = get_bytecode(CONSTRUCTOR_EMPTY_EVENT)
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver)

    sevm.run(exec)
    render_trace(exec.call_frame)

    assert exec.call_frame.output.error is None
    assert len(exec.call_frame.trace) == 1

    event: EventLog = exec.call_frame.trace[0]
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == FOO_EVENT_SIG
    assert event.data is None


def test_simple_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(SIMPLE_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.call_frame)

    assert exec.call_frame.output is not None
    assert exec.call_frame.output.error is None

    # go() returns success=true
    assert int_of(exec.call_frame.output.data) == 1

    # view_func() returns 42
    subcalls = exec.call_frame.subcalls()
    assert len(subcalls) == 1
    assert subcalls[0].output.error is None
    assert int_of(subcalls[0].output.data) == 42


def test_failed_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_SIMPLE_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.call_frame)

    # go() does not revert, it returns success=false
    assert exec.call_frame.output.error is None
    assert int_of(exec.call_frame.output.data) == 0

    # the just_fails() subcall fails
    subcalls = exec.call_frame.subcalls()
    assert len(subcalls) == 1
    assert subcalls[0].output.error is Revert
    assert int_of(subcalls[0].output.data) == PANIC_1


def test_failed_static_call(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(FAILED_STATIC_CALL)
    input_exec: Exec = mk_ex(runtime_hexcode, sevm, solver)

    execs = sevm.run(input_exec)[0]
    assert len(execs) == 1

    exec = execs.pop()
    render_trace(exec.call_frame)

    # go() does not revert, it returns success=false
    assert exec.call_frame.output.error is None
    assert int_of(exec.call_frame.output.data) == 0

    # the do_sstore() subcall fails
    subcalls = exec.call_frame.subcalls()
    assert len(subcalls) == 1
    assert subcalls[0].message.is_static is True
    assert isinstance(subcalls[0].output.error, WriteInStaticContext)


def test_symbolic_subcall(sevm: SEVM, solver):
    _, runtime_hexcode = get_bytecode(SYMBOLIC_SUBCALL)
    input_exec: Exec = mk_ex(
        runtime_hexcode, sevm, solver, data=symbolic_uint256_calldata
    )

    execs = sevm.run(input_exec)[0]

    # we get 2 executions, one for x == 42 and one for x != 42
    assert len(execs) == 2
    render_trace(execs[0].call_frame)
    render_trace(execs[1].call_frame)

    # all executions have exactly one subcall and the outer call does not revert
    assert all(len(x.call_frame.subcalls()) == 1 for x in execs)
    assert all(x.call_frame.output.error is None for x in execs)

    # in one of the executions, the subcall succeeds
    assert any(x.call_frame.subcalls()[0].output.error is None for x in execs)

    # in one of the executions, the subcall reverts
    assert any(x.call_frame.subcalls()[0].output.error is Revert for x in execs)
