// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {ERC1155, IERC1155} from "openzeppelin/token/ERC1155/ERC1155.sol";
import {ERC1155Holder} from "openzeppelin/token/ERC1155/utils/ERC1155Holder.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

uint256 constant TOKEN_ID = 1;

contract ERC1155Mock is ERC1155 {
    constructor() ERC1155("URI") {
        _mint(msg.sender, TOKEN_ID, 1_000_000_000 ether, "");
    }
}

contract BuggyVault is ERC1155Holder, ReentrancyGuard {
    mapping(address => uint) balances;
    IERC1155 token;

    constructor (IERC1155 _token) {
        token = _token;
    }

    function deposit(uint value) public payable {
        token.safeTransferFrom(msg.sender, address(this), TOKEN_ID, value, "");
        balances[msg.sender] += value;
    }

    // ReentrancyTest will pass if nonReentrant is applied
    function withdraw() public /* nonReentrant */ {
        uint balance = balances[msg.sender];
        // reentrancy vulnerability
        token.safeTransferFrom(address(this), msg.sender, TOKEN_ID, balance, "");
        balances[msg.sender] = 0;
    }
}

contract Attacker is SymTest, Test {
    uint depth; // reentrancy depth
    address target; // reentrancy target

    function setDepth(uint _depth) public {
        depth = _depth;
    }

    function setTarget(address _target) public {
        target = _target;
    }

    function onERC1155Received(
        address, /* operator */
        address, /* from */
        uint256, /* id */
        uint256, /* value */
        bytes calldata /* data */
    ) external returns (bytes4) {
        if (depth == 0) return this.onERC1155Received.selector;
        depth--;

        bytes memory data = svm.createCalldata(target);
        (bool success,) = target.call(data);
        vm.assume(success);

        return this.onERC1155Received.selector;
    }
}

/// @custom:halmos --early-exit
contract ReentrancyTest is Test, ERC1155Holder {
    ERC1155Mock token;
    BuggyVault vault;
    Attacker attacker;

    uint256 constant ATTACKER_INITIAL_BALANCE = 100_000_000 ether;

    function setUp() public {
        token = new ERC1155Mock();

        // deploy vault with initial deposit
        vault = new BuggyVault(IERC1155(token));
        token.setApprovalForAll(address(vault), true);
        vault.deposit(1_000_000 ether);

        // deploy attacker with initial balance
        attacker = new Attacker();
        token.safeTransferFrom(address(this), address(attacker), TOKEN_ID, ATTACKER_INITIAL_BALANCE, "");

        // make attacker's initial deposit into vault
        vm.startPrank(address(attacker));
        token.setApprovalForAll(address(vault), true);
        vault.deposit(1_000_000 ether);
        vm.stopPrank();

        // configure attacker
        attacker.setDepth(1);
        attacker.setTarget(address(vault));

        targetContract(address(vault));

        // check setup
        assertEq(token.balanceOf(address(this), TOKEN_ID), 999_000_000 ether - ATTACKER_INITIAL_BALANCE);
        assertEq(token.balanceOf(address(attacker), TOKEN_ID), 99_000_000 ether);
        assertEq(token.balanceOf(address(vault), TOKEN_ID), 2_000_000 ether);
    }

    function invariant_no_stolen_funds() public view {
        assertLe(token.balanceOf(address(attacker), TOKEN_ID), ATTACKER_INITIAL_BALANCE);
    }
}
