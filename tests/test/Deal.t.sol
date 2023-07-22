// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract DealTest is Test {
    C c;

    function check_deal_1(address payable receiver, uint amount) public {
        vm.deal(receiver, amount);
        assert(receiver.balance == amount);
    }

    function check_deal_2(address payable receiver, uint amount1, uint amount2) public {
        vm.deal(receiver, amount1);
        vm.deal(receiver, amount2); // reset the balance, not increasing
        assert(receiver.balance == amount2);
    }

    function check_deal_new() public {
        vm.deal(address(this), 3 ether);

        c = new C{value: 3 ether}();

        assertGe(address(c).balance, 3 ether); // it is possible to send ether to c before it is created
        assert(address(this).balance == 0 ether);
    }
}

contract C {
    constructor() payable { }
}
