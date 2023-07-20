// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract NatspecTestNone {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function checkLoop2(uint n) public view {
        assert(l.iter(n) <= 2); // pass // default
    }
    function checkLoop2Fail(uint n) public view {
        assert(l.iter(n) <= 1); // fail // default
    }
}

/// @custom:halmos --loop 3
contract NatspecTestContract {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function checkLoop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass // inherited from contract
    }
    function checkLoop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail // inherited from contract
    }
}

contract NatspecTestSetup {
    Loop l;

    /// @custom:halmos --loop 3
    function setUp() public {
        l = new Loop();
    }

    function checkLoop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass // inherited from setup
    }
    function checkLoop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail // inherited from setup
    }
}

contract NatspecTestFunction {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    /// @custom:halmos --loop 3
    function checkLoop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass
    }
    /// @custom:halmos --loop 3
    function checkLoop3Fail(uint n) public view {
        assert(l.iter(n) <= 2); // fail
    }

    function checkLoop2(uint n) public view {
        assert(l.iter(n) <= 2); // pass // default
    }
    function checkLoop2Fail(uint n) public view {
        assert(l.iter(n) <= 1); // fail // default
    }
}

/// @custom:halmos --loop 4
contract NatspecTestOverwrite {
    Loop l;

    function setUp() public {
        l = new Loop();
    }

    function checkLoop4(uint n) public view {
        assert(l.iter(n) <= 4); // pass // inherited from contract
    }
    function checkLoop4Fail(uint n) public view {
        assert(l.iter(n) <= 3); // fail // inherited from contract
    }

    /// @custom:halmos --loop 3
    function checkLoop3(uint n) public view {
        assert(l.iter(n) <= 3); // pass // overwrite
    }
    /// @custom:halmos --loop 3
    function checkLoop3Fail(uint n) public view {
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
