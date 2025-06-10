// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num1;
    uint public num2;

    function f1() public {
        num1++;
    }

    function f2() public {
        num2++;
    }
}

contract D {
    uint public num3;
    uint public num4;

    function f3() public {
        num3++;
    }

    function f4() public {
        num4++;
    }
}

abstract contract InvariantTargetTest is Test {
    C c;
    D d;

    uint public num0;

    function f0() public {
        num0++;
    }

    function invariant_0() public {
        assertLt(num0, 2);
    }

    function invariant_1() public {
        assertLt(c.num1(), 2);
    }

    function invariant_2() public {
        assertLt(c.num2(), 2);
    }

    function invariant_3() public {
        assertLt(d.num3(), 2);
    }

    function invariant_4() public {
        assertLt(d.num4(), 2);
    }
}

contract InvariantTargetTest_0_1_2_3 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        // targetContract(address(this)); // not needed, due to targetSelector() below
        selectors = new bytes4[](1);
        selectors[0] = this.f0.selector;
        targetSelector(FuzzSelector({addr: address(this), selectors: selectors}));

        targetContract(address(c));

        // targetContract(address(d)); // not needed, due to targetSelector() below
        selectors = new bytes4[](1);
        selectors[0] = d.f3.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors}));
    }
}

contract InvariantTargetTest_target_contract_this is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        // https://github.com/a16z/halmos/issues/506
        // C and D are not set as a targets, because targetContract(address(this)) is used
        targetContract(address(this));
    }
}

contract InvariantTargetTest_all is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        // the test contract is included due to targetSelector() below.
        // since targetContract() is not invoked, all other deployed contracts are also considered as a target.
        // targetContract(address(this));
        selectors = new bytes4[](1);
        selectors[0] = this.f0.selector;
        targetSelector(FuzzSelector({addr: address(this), selectors: selectors}));
    }
}

contract InvariantTargetTest_0 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        // since targetContract() is explicitly given, only the test contract is set as a target.
        targetContract(address(this));
        selectors = new bytes4[](1);
        selectors[0] = this.f0.selector;
        targetSelector(FuzzSelector({addr: address(this), selectors: selectors}));
    }
}

contract InvariantTargetTest_1_2 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        // all selectors in C are targeted
        targetContract(address(c));
    }
}

contract InvariantTargetTest_3 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        // only the given selectors are targeted
        targetContract(address(d));
        selectors = new bytes4[](1);
        selectors[0] = d.f3.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors}));
    }
}
