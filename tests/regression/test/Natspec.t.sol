// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract NatspecTestNone {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function check_Loop2(uint n) public view {
        assert(l.iter(n) <= 2); // pass // default
    }
    function check_Loop2Fail(uint n) public view {
        assert(l.iter(n) <= 1); // fail // default
    }
}

/// @custom:halmos --loop 3
contract NatspecTestContract {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function check_Loop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass // inherited from contract
    }
    function check_Loop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail // inherited from contract
    }
}

contract NatspecTestSetup {
    Loop l;

    /// @custom:halmos --loop 3
    function setUp() public {
        l = new Loop();
    }

    function check_Loop2(uint n) public view {
        assert(l.iter(n) <= 2); // pass // default
    }
    function check_Loop2Fail(uint n) public view {
        assert(l.iter(n) <= 1); // fail // default
    }
}

contract NatspecTestFunction {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    /// @custom:halmos --loop 3
    function check_Loop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass
    }
    /// @custom:halmos --loop 3
    function check_Loop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail
    }

    function check_Loop2(uint n) public view {
        assert(l.iter(n) <= 2); // pass // default
    }
    function check_Loop2Fail(uint n) public view {
        assert(l.iter(n) <= 1); // fail // default
    }
}

/// @custom:halmos --loop 4
contract NatspecTestOverwrite {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function check_Loop4(uint n) public view {
        assert(l.iter(n) <= 4); // pass // inherited from contract
    }
    function check_Loop4Fail(uint n) public view {
        assert(l.iter(n) <= 3); // fail // inherited from contract
    }

    /// @custom:halmos --loop 3
    function check_Loop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass // overwrite
    }
    /// @custom:halmos --loop 3
    function check_Loop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail // overwrite
    }
}

contract Loop {
    function iter(uint n) public pure returns (uint) {
        uint cnt = 0;
        for (uint i = 0; i < n; i++) {
            cnt++;
        }
        return cnt;
    }
}
