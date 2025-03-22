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

    function check_RevertBalance_Known(bool paused, uint256 amount) public {
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

    function check_RevertBalance_Unknown(uint256 balance, uint256 amount) public {
        vm.deal(address(this), balance);
        vm.assume(amount > balance);

        (bool result, ) = address(42).call{value: amount}("");

        assert(!result);
        assertEq(address(this).balance, balance);
        assertEq(address(42).balance, 0);
    }

    function check_BalanceTransfer_Known(uint256 balance, uint256 amount) public {
        // balance and amount are unconstrained, so could fail, could succeed
        vm.deal(address(this), balance);

        (bool success, ) = address(c).call{value: amount}(abi.encodeWithSignature("deposit(bool)", false));

        // we are looking for a counterexample here
        // i.e., halmos should find the case amount > balance
        assert(success);
    }

    function check_BalanceTransfer_Unknown(uint256 balance, uint256 amount) public {
        // balance and amount are unconstrained, so could fail, could succeed
        vm.deal(address(this), balance);

        (bool success, ) = address(42).call{value: amount}("");

        // we are looking for a counterexample here
        // i.e., halmos should find the case amount > balance
        assert(success);
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
