# pragma version ~=0.4.3
"""
@title Symbolic tests written in Vyper
@custom:dolmos --loop 3
"""

interface ICounter:
    def count() -> uint256: view
    def add(x: uint256): nonpayable


interface Vm:
    def assume(c: bool): nonpayable
    def assertEq(a: uint256, b: uint256): nonpayable
    def getCode(path: String[64]) -> Bytes[4096]: view


VM: constant(address) = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D

counter: ICounter


@external
def setUp():
    code: Bytes[4096] = staticcall Vm(VM).getCode("Counter.vy:Counter")
    self.counter = ICounter(raw_create(code))


@external
def check_add_unreachable(x: uint256):
    # expected to fail (x == 13): UNREACHABLE compiles to the INVALID opcode
    before: uint256 = staticcall self.counter.count()
    extcall self.counter.add(x)
    assert staticcall self.counter.count() == before + x, UNREACHABLE


@external
def check_add_cheatcode(x: uint256):
    # expected to fail (x == 13): hevm assertion cheatcodes work from vyper too
    before: uint256 = staticcall self.counter.count()
    extcall self.counter.add(x)
    extcall Vm(VM).assertEq(staticcall self.counter.count(), before + x)


@external
def check_add_ok(x: uint256):
    extcall Vm(VM).assume(x != 13)
    before: uint256 = staticcall self.counter.count()
    extcall self.counter.add(x)
    assert staticcall self.counter.count() == before + x, UNREACHABLE


@external
def check_plain_assert(x: uint256):
    # a plain `assert` is an empty revert, indistinguishable from a `require`:
    # the path is discarded, not reported
    assert x != 13


@external
def check_bytes_default(data: Bytes[100]):
    # expected to fail: 65 is one of the default bytes lengths
    assert len(data) != 65, UNREACHABLE


@external
def check_bytes_annotated(data: Bytes[100]):
    """
    @custom:dolmos --default-bytes-lengths 0,10
    """
    assert len(data) != 65, UNREACHABLE
