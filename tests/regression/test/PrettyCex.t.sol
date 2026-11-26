// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract PcexToken {
    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = 1000;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    receive() external payable {}
}

/// counterexamples of the issues addressed by --pretty-counterexamples, see tests/test_pcex.py
/// @custom:dolmos --solver-timeout-assertion 0 --invariant-depth 1
contract PrettyCexTest is Test, SymTest {
    PcexToken token;

    function setUp() public {
        token = new PcexToken();
    }

    // halmos#398: the same counterexample for 3 paths
    function check_pcex_duplicates(uint256 x) external pure {
        uint256 mul = x * 42;
        assertNotEq(mul, 0);
        assertNotEq(mul, 0);
        assertNotEq(mul, 0);
    }

    // halmos#280: x ** 3 is approximated, the only real counterexample is x == 3
    function check_pcex_exp(uint256 x) external pure {
        assert(x ** 3 != 27);
    }

    // halmos#369: arbitrary calldata
    function check_pcex_calldata(bytes calldata data) external {
        (bool ok,) = address(token).call(data);
        assert(!ok || token.balanceOf(address(this)) == 1000);
    }

    // halmos#419: the empty selector of plain ether transfers
    function check_pcex_selector(bytes calldata data) external {
        bytes4 selector = svm.createBytes4("selector");
        vm.assume(bytes4(data) == selector);
        (bool ok,) = address(token).call(data);
        assert(!(ok && data.length == 0));
    }

    // call sequence with concrete values
    function invariant_pcex_balance() public view {
        assertGe(token.balanceOf(address(this)), 1000);
    }
}
