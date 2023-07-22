// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract C {
    function foo() public pure returns (uint) {
        return 1;
    }
}

/// @custom:halmos --reset-bytecode 0xaaaa0002=0x6080604052348015600f57600080fd5b506004361060285760003560e01c8063c298557814602d575b600080fd5b600260405190815260200160405180910390f3fea2646970667358221220c2880ecd3d663c2d8a036163ee7c5d65b9a7d1749e1132fd8ff89646c6621d5764736f6c63430008130033
contract ResetTest {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_foo() public view {
        assert(c.foo() == 2); // for testing --reset-bytecode option
    }

}
