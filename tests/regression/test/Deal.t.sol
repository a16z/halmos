// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract DealTest is Test {
    uint256 constant MAX_ETH = 1 << 128;
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

    // finds an empty counterexample along with a warning about the large balance
    function check_deal_over_max_eth_concrete() public {
        uint256 too_much = MAX_ETH + 1 ether;
        vm.deal(address(this), too_much);
        assertNotEq(address(this).balance, too_much);
    }

    function check_deal_over_max_eth_mixed(address addr) public {
        uint256 too_much = MAX_ETH + 1 ether;
        vm.deal(address(this), too_much);

        // cex won't be found because of the constraint on large balances < MAX_ETH
        assertLe(addr.balance, MAX_ETH);
    }

    function check_deal_under_max_eth_mixed(address addr) public {
        uint256 large_but_ok = MAX_ETH - 1 ether;
        vm.deal(address(this), large_but_ok);

        // cex can be found
        assertLe(addr.balance, MAX_ETH / 2);
    }
}

contract C {
    constructor() payable { }
}
