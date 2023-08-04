// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract TestConstructorTest {
    uint initialized = 1;
    uint constant const = 2;
    uint immutable flag;
    uint value;
    uint codesize_;
    uint extcodesize_;

    constructor () {
        flag = 3;
        value = 4;

        assembly {
            sstore(codesize_.slot, codesize())
            sstore(extcodesize_.slot, extcodesize(address()))
        }
    }

    function check_value() public view {
        assert(initialized == 1);
        assert(const == 2);
        assert(flag == 3);
        assert(value == 4);

        assert(codesize_ > 0);
        assert(extcodesize_ == 0);
    }
}
