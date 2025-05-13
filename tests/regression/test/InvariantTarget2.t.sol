// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {C, D, InvariantTargetTest} from "./InvariantTarget.t.sol";

contract InvariantTargetTest_excludeContract_0_0 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        // target: *
    }
}

contract InvariantTargetTest_excludeContract_0_1 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        targetContract(address(c));

        excludeContract(address(c));

        // target: {}
    }
}

contract InvariantTargetTest_excludeContract_0_2 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        excludeContract(address(c));

        // target: * - {c}
    }
}

contract InvariantTargetTest_excludeContract_0_3 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        targetContract(address(c));

        bytes4[] memory selectors;
        selectors = new bytes4[](1);
        selectors[0] = c.f1.selector;
        targetSelector(FuzzSelector({addr: address(c), selectors: selectors}));

        excludeContract(address(c));

        // target: {c.f1}
    }
}

contract InvariantTargetTest_excludeContract_0_4 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;
        selectors = new bytes4[](1);
        selectors[0] = c.f1.selector;
        targetSelector(FuzzSelector({addr: address(c), selectors: selectors}));

        excludeContract(address(c));

        // target: {c.f1, d.*}
    }
}

contract InvariantTargetTest_excludeContract_1 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        targetContract(address(c));

        targetContract(address(d));

        excludeContract(address(d));

        // target: {c}
    }
}

contract InvariantTargetTest_excludeContract_2 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        targetContract(address(c));

        excludeContract(address(d));

        targetContract(address(d));

        // target: {c}
    }
}

contract InvariantTargetTest_excludeSelector_1 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        targetContract(address(c)); // target: c.*

        // if targetSelector is given, excludeSelector is ignored

        selectors = new bytes4[](2);
        selectors[0] = d.f3.selector;
        selectors[1] = d.f4.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3,f4}

        selectors = new bytes4[](1);
        selectors[0] = d.f4.selector;
        excludeSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3,f4}
    }
}

contract InvariantTargetTest_excludeSelector_2 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        targetContract(address(c)); // target: c.*

        // if targetSelector is given, excludeSelector is ignored

        selectors = new bytes4[](1);
        selectors[0] = d.f3.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3}

        selectors = new bytes4[](1);
        selectors[0] = d.f4.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3,f4}

        selectors = new bytes4[](1);
        selectors[0] = d.f4.selector;
        excludeSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3,f4}
    }
}

contract InvariantTargetTest_excludeSelector_3 is InvariantTargetTest {
    function setUp() public {
        c = new C();
        d = new D();

        bytes4[] memory selectors;

        targetContract(address(c)); // target: c.*

        // if targetSelector is given, excludeSelector is ignored

        selectors = new bytes4[](1);
        selectors[0] = d.f3.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3}

        selectors = new bytes4[](1);
        selectors[0] = d.f4.selector;
        targetSelector(FuzzSelector({addr: address(d), selectors: selectors})); // target: c.*, d.{f3,f4}

        selectors = new bytes4[](1);
        selectors[0] = c.f1.selector;
        excludeSelector(FuzzSelector({addr: address(c), selectors: selectors})); // target: c.{f2}, d.{f3,f4}
    }
}
