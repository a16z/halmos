import json
import pytest
import subprocess

from typing import Dict

from z3 import *

from halmos.__main__ import mk_block, render_trace
from halmos.exceptions import *
from halmos.sevm import Exec, Contract, Message, CallFrame, EventLog, con, int_of
from halmos.utils import EVM
from test_fixtures import args, options, sevm

# keccak256("FooEvent()")
FOO_EVENT_SIG = 0x34E21A9428B1B47E73C4E509EABEEA7F2B74BECA07D82AAC87D4DD28B74C2A4A

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

caller = BitVec("msg_sender", 160)
this = BitVec("this_address", 160)
balance = Array("balance_0", BitVecSort(160), BitVecSort(256))
callvalue = BitVec("msg_value", 256)


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
    hexcode, sevm, solver, caller=caller, value=callvalue, this=this, storage={}
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
        code={this: {}},
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
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(0))

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
    exec: Exec = mk_create_ex(deploy_hexcode, sevm, solver, value=con(0))

    sevm.run(exec)
    render_trace(exec.call_frame)

    assert exec.call_frame.output.error is None
    assert len(exec.call_frame.trace) == 1

    event: EventLog = exec.call_frame.trace[0]
    assert len(event.topics) == 1
    assert int_of(event.topics[0]) == FOO_EVENT_SIG
    assert event.data is None
