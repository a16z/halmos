// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from https://github.com/a16z/halmos/issues/82

/// @custom:halmos --custom-storage-layout
contract GetterTest {
    uint256[3] v;
    uint w;

    function check_Getter(uint256 i) public view {
        assert(v[i] >= 0);
    }
}
