// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

// functional correctness test for the system contract bytecode in https://eips.ethereum.org/EIPS/eip-2935

/*
 *  At the beginning of processing a block where `block.number == 8192*k + i`,
 *  the `set` operation updates the storage as follows, where `calldata[0:32] == blockhash(8192*k + i-1)`:
 *
 *      Slot    Data                                        New data after `set` operation
 *
 *        0     blockhash(8192* k    +  0   )               <unchanged>
 *        1     blockhash(8192* k    +  1   )               <unchanged>
 *       ...    ...                                         ...
 *       i-2    blockhash(8192* k    + i-2  )               <unchanged>
 *       i-1    blockhash(8192*(k-1) + i-1  )   == set ==>  blockhash(8192*k + i-1)
 *        i     blockhash(8192*(k-1) +  i   )               <unchanged>
 *       ...    ...                                         ...
 *      8190    blockhash(8192*(k-1) + 8190 )               <unchanged>
 *      8191    blockhash(8192*(k-1) + 8191 )               <unchanged>
 *      8192    0                                           <unchanged>
 *       ...    ...                                         ...
 *   2^256-1    0                                           <unchanged>
 *
 *  Then, during the processing of the block at `8192*k + i`,
 *  the `get` operation reads the storage at the slot `calldata[0:32] % 8192`,
 *  as long as `calldata[0:32]` falls within the range `[8192*(k-1) + i, 8192*k + i-1]` (inclusive).
 *  Otherwise, it returns 0.
 */

/*
 *  Edge cases:
 *
 *  When `block.number == 0`:
 *  - The `set` operation updates slot 8191 with the given `calldata[0:32]` value.
 *    If this value is non-zero, it could lead to storage corruption.
 *  - The `get` operation reads from slot `calldata[0:32] % 8192`, rather than immediately returning 0.
 *    If the storage is corrupted, this operation may retrieve corrupted data.
 *  - While this is not relevant to the Ethereum chain, it could pose issues for other EVM chains upon creation.
 */

/// @custom:halmos --storage-layout generic
contract EIP2935Test is SymTest, Test {
    address constant HISTORY_STORAGE_ADDRESS = address(0x0AAE40965E6800cD9b1f4b05ff21581047E3F91e);
    address constant SYSTEM_ADDRESS = address(0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE);

    uint constant HISTORY_SERVE_WINDOW = 8192;

    uint blocknumber;

    function setUp() public {
        // set the bytecode given in https://eips.ethereum.org/EIPS/eip-2935
        vm.etch(HISTORY_STORAGE_ADDRESS, hex"3373fffffffffffffffffffffffffffffffffffffffe1460575767ffffffffffffffff5f3511605357600143035f3511604b575f35612000014311604b57611fff5f3516545f5260205ff35b5f5f5260205ff35b5f5ffd5b5f35611fff60014303165500");

        svm.enableSymbolicStorage(HISTORY_STORAGE_ADDRESS);

        blocknumber = svm.createUint256("block.number");
        vm.roll(blocknumber);

        vm.fee(svm.createUint256("block.basefee"));
        vm.chainId(svm.createUint256("block.chainid"));
        vm.coinbase(svm.createAddress("block.coinbase"));
        vm.difficulty(svm.createUint256("block.difficulty"));
        vm.warp(svm.createUint256("block.timestamp"));

        // TODO: what's the expected behavior when blocknumber == 0?
        vm.assume(blocknumber > 0);
    }

    function check_invariant(address caller, uint value) public {
        // TODO: what's the expected behavior when caller is HISTORY_STORAGE_ADDRESS?
        vm.assume(caller != HISTORY_STORAGE_ADDRESS);

        // set balances
        uint old_HISTORY_STORAGE_ADDRESS_balance = svm.createUint(96, "HISTORY_STORAGE_ADDRESS.balance");
        uint old_caller_balance = svm.createUint(96, "caller.balance");
        vm.deal(HISTORY_STORAGE_ADDRESS, old_HISTORY_STORAGE_ADDRESS_balance);
        vm.deal(caller, old_caller_balance);

        // record other storage slots
        uint other_slot = svm.createUint256("other_slot");
        vm.assume(other_slot >= HISTORY_SERVE_WINDOW);
        bytes32 old_other_slot_value = vm.load(HISTORY_STORAGE_ADDRESS, bytes32(other_slot));

        // arbitrary calldata
        bytes memory data = svm.createBytes(1024, "data");

        // call HISTORY_STORAGE_ADDRESS
        vm.prank(caller);
        (bool success, bytes memory retdata) = HISTORY_STORAGE_ADDRESS.call{value: value}(data);

        // check get operation
        if (caller != SYSTEM_ADDRESS) {
            uint input = uint(bytes32(data));
            if (input < 2**64) {
                assertTrue(success);
                bytes32 output = bytes32(retdata);
                // blocknumber - HISTORY_SERVE_WINDOW <= input <= blocknumber - 1
                if (input + HISTORY_SERVE_WINDOW >= blocknumber && input + 1 <= blocknumber) {
                    assertEq(output, vm.load(HISTORY_STORAGE_ADDRESS, bytes32(input % HISTORY_SERVE_WINDOW)));
                } else {
                    assertEq(output, 0);
                }
            } else {
                assertFalse(success);
            }
        // check set operation
        } else {
            bytes32 input = bytes32(data);
            assertTrue(success);
            assertEq(input, vm.load(HISTORY_STORAGE_ADDRESS, bytes32((blocknumber - 1) % HISTORY_SERVE_WINDOW)));
        }

        // check balance updates
        _check_balance_update(caller, value, success, old_HISTORY_STORAGE_ADDRESS_balance, old_caller_balance);

        // check other storage slots
        _check_other_storage_slots(other_slot, old_other_slot_value);
    }

    function _check_balance_update(address caller, uint value, bool success, uint old_HISTORY_STORAGE_ADDRESS_balance, uint old_caller_balance) internal {
        if (success) {
            assertEq(HISTORY_STORAGE_ADDRESS.balance, old_HISTORY_STORAGE_ADDRESS_balance + value);
            assertEq(caller.balance, old_caller_balance - value);
        } else {
            assertEq(HISTORY_STORAGE_ADDRESS.balance, old_HISTORY_STORAGE_ADDRESS_balance);
            assertEq(caller.balance, old_caller_balance);
        }
    }

    function _check_other_storage_slots(uint other_slot, bytes32 old_other_slot_value) internal {
        bytes32 new_other_slot_value = vm.load(HISTORY_STORAGE_ADDRESS, bytes32(other_slot));
        assertEq(new_other_slot_value, old_other_slot_value);
    }
}
