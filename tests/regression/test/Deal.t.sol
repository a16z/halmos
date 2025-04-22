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

    // raises an error
    function check_deal_over_max_eth() public {
        uint256 too_much = MAX_ETH + 1 ether;
        vm.deal(address(this), too_much);
        assertNotEq(address(this).balance, too_much);
    }

    // raises an error
    function check_deal_over_max_eth(address addr) public {
        uint256 too_much = MAX_ETH + 1 ether;
        vm.deal(addr, too_much);
        assertLe(addr.balance, MAX_ETH);
    }

    function check_deal_over_max_eth(uint256 value) public {
        // keep the value symbolic, but guarantee the value is greater than MAX_ETH
        vm.deal(address(this), 1 << 255 | value);
        assertLe(address(this).balance, MAX_ETH);
    }

    function check_deal_over_max_eth(address addr, uint256 value) public {
        // keep the value symbolic, but guarantee the value is greater than MAX_ETH
        vm.deal(addr, 1 << 255 | value);
        assertLe(addr.balance, MAX_ETH);
    }

    function check_concretized_transfer_over_max_eth(bytes memory data) public {
        address payable to = payable(address(0x42));
        vm.deal(to, MAX_ETH);

        // this should be concretized to:
        // - a path where data.length == 0, so the transfer succeeds and the assert passes
        // - one or more paths where data.length > 0, so the assert fails
        // (more precisely the balance update/retrieval will fail)
        to.transfer(data.length);
        assertLe(to.balance, MAX_ETH);
    }

    function check_implicit_transfer_over_max_eth(uint256 x) public {
        vm.assume(x <= address(this).balance);

        address payable to = payable(address(0x42));
        vm.deal(to, MAX_ETH - 1);

        to.transfer(x);

        // if we don't load to's balance, the constraint on x is not added to the path
        console.log("to.balance", to.balance);

        // can x be greater than 1? nope! so this is a PASS
        assertLe(x, 1);
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
