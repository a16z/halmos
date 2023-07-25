// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from https://github.com/a16z/halmos/issues/109

import "forge-std/Test.sol";

contract A { }

contract C {
    uint256 public num;

    function set1(uint256 x) public {
        num = x;
        revert("blah");
    }

    function set2(uint256 x) public {
        revert("blah");
        num = x;
    }

    function deposit(bool paused) public payable {
        if (paused) revert("paused");
    }

    function create() public {
        A a = new A();
        revert(string(abi.encode(a)));
    }
}

contract CTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_Revert1(uint256 x) public {
        require(x != 0);
        (bool result, ) = address(c).call(abi.encodeWithSignature("set1(uint256)", x));
        assert(!result);
        assert(c.num() != x);
    }

    function check_Revert2(uint256 x) public {
        require(x != 0);
        (bool result, ) = address(c).call(abi.encodeWithSignature("set2(uint256)", x));
        assert(!result);
        assert(c.num() != x);
    }

    function check_RevertBalance(bool paused, uint256 amount) public {
        vm.deal(address(this), amount);
        vm.deal(address(c), 0);

        (bool result,) = address(c).call{value: amount}(abi.encodeWithSignature("deposit(bool)", paused));

        if (result) {
            assert(!paused);
            assert(address(this).balance == 0);
            assert(address(c).balance == amount);
        } else {
            assert(paused);
            assert(address(this).balance == amount);
            assert(address(c).balance == 0);
        }
    }

    function codesize(address x) internal view returns (uint256 size) {
        assembly { size := extcodesize(x) }
    }

    function check_RevertCode(address x) public {
        uint256 oldSize = codesize(x);
        try c.create() {
        } catch Error(string memory s) {
            address a = abi.decode(bytes(s), (address));
            uint256 size = codesize(a);
            vm.assume(a == x);
            assert(size == oldSize);
        }
    }
}
