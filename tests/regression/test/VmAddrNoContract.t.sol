// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;
import "forge-std/Test.sol";
contract VmAddrDummy { function f() external pure returns (uint) { return 1; } }
/// vm.addr never returns the address of a contract (halmos#413)
contract VmAddrNoContractTest is Test {
    VmAddrDummy d;
    address constant ETCHED = 0x1234567890123456789012345678901234567890;
    function setUp() public {
        d = new VmAddrDummy();
        vm.etch(ETCHED, address(d).code);
    }
    function check_vmaddr_not_deployed(uint256 key) public {
        address a = vm.addr(key);
        assert(a != address(d));
        assert(a != ETCHED);
        assert(a != address(this));
    }
    function check_vmaddr_can_be_anything_else_fail(uint256 key) public {
        // sanity: vm.addr is not over-constrained
        assert(vm.addr(key) != address(0x1111111111111111111111111111111111111111));
    }
}
