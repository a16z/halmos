// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/// @notice the annotation selects the tests of this contract
/// @dev see upstream halmos issue #184
/// @custom:dolmos --function verify_
contract NatspecFunctionTest {
    function verify_selected(uint256 x) public pure {
        assert(x == x);
    }

    // not selected: the annotation replaces the default prefix
    function check_not_selected(uint256 x) public pure {
        assert(x != 42);
    }
}

/// @custom:dolmos --match-test selected
contract NatspecMatchTest {
    function check_selected(uint256 x) public pure {
        assert(x == x);
    }

    function check_other(uint256 x) public pure {
        assert(x != 42);
    }
}
