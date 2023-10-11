// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract C {
    uint public codesize_;
    uint public extcodesize_;

    constructor () {
        setCodesize();
    }

    function setCodesize() public {
        assembly {
            sstore(codesize_.slot, codesize())
            sstore(extcodesize_.slot, extcodesize(address()))
        }
    }
}

contract ConstructorTest {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_constructor() public {
        assert(c.codesize_() > 0); // contract creation bytecode size
        assert(c.extcodesize_() == 0); // code is not yet deposited in the network state during constructor()
    }

    function check_setCodesize() public {
        uint creation_codesize = c.codesize_();

        c.setCodesize();

        assert(c.codesize_() > 0); // deployed bytecode size
        assert(c.extcodesize_() > 0); // deployed bytecode size
        assert(c.codesize_() == c.extcodesize_());

        assert(c.codesize_() < creation_codesize); // deployed bytecode is smaller than creation bytecode
    }
}
