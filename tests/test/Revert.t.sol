// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from https://github.com/a16z/halmos/issues/109

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
}

contract CTest {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_Revert1(uint256 x) public {
        require(x != 0);
        (bool result, ) = address(c).call(abi.encodeWithSignature("set1(uint256)", x));
        assert(!result);
        assert(c.num() != x); // fail // TODO: fix reverting semantics
    }

    function check_Revert2(uint256 x) public {
        require(x != 0);
        (bool result, ) = address(c).call(abi.encodeWithSignature("set2(uint256)", x));
        assert(!result);
        assert(c.num() != x);
    }
}
