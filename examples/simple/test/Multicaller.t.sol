// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {MulticallerWithSender} from "multicaller/MulticallerWithSender.sol";

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

// An unoptimized reference implementation of MulticallerWithSender.
// This serves as a baseline for comparison against the optimized version, to verify the correctness of optimizations.
contract MulticallerWithSenderSpec {
    error ArrayLengthsMismatch();

    error Reentrancy();

    address public sender;
    bool public reentrancyUnlocked;

    constructor() payable {
        reentrancyUnlocked = true;
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (data.length > 0) revert();
        return abi.encode(sender);
    }

    function aggregateWithSender(
        address[] calldata targets,
        bytes[] calldata data,
        uint256[] calldata values
    ) external payable returns (bytes[] memory) {
        if (targets.length != data.length || data.length != values.length) {
            revert ArrayLengthsMismatch();
        }

        if (!reentrancyUnlocked) {
            revert Reentrancy();
        }

        bytes[] memory results = new bytes[](data.length);

        if (data.length == 0) {
            return results;
        }

        // Lock
        sender = msg.sender;
        reentrancyUnlocked = false;

        for (uint i = 0; i < data.length; i++) {
            (bool success, bytes memory retdata) = targets[i].call{value: values[i]}(data[i]);
            if (!success) {
                _revertWithReturnData();
            }
            results[i] = retdata;
        }

        // Unlock
        sender = address(0);
        reentrancyUnlocked = true;

        return results;
    }

    function _revertWithReturnData() internal pure {
        assembly {
            returndatacopy(0, 0, returndatasize())
            revert(0, returndatasize())
        }
    }
}

contract MulticallerWithSenderMock is MulticallerWithSender {
    // Provide public getters for the storage variables.
    // Note: the variable order is set to align with the packing scheme used by the implementation.
    address public sender;
    bool public reentrancyUnlocked;
}

// A mock target contract that keeps track of external calls made via Multicaller
contract TargetMock is SymTest {
    // Record of values received from each caller.
    mapping (address => uint) private balanceOf;

    fallback(bytes calldata data) external payable returns (bytes memory) {
        balanceOf[msg.sender] += msg.value;

        // Simulate deterministically random behaviors.
        uint256 mode = msg.value & 255;
        if (mode == 0) {
            // Call multicaller fallback which should return the multicaller sender.
            (bool success, bytes memory retdata) = msg.sender.call("");
            return abi.encode(success, retdata);
        } else if (mode == 1) {
            // Reenter multicaller aggregateWithSender, which should revert.
            (bool success, bytes memory retdata) = msg.sender.call(abi.encodeWithSelector(MulticallerWithSender.aggregateWithSender.selector, new address[](0), new bytes[](0), new uint256[](0)));
            return abi.encode(success, retdata);
        } else if (mode == 2) {
            // Return the callvalue and calldata, which can then be retrieved later when checking the results of multicalls.
            return abi.encode(msg.value, data);
        } else {
            revert();
        }
    }
}

// Check equivalence between the implementation and the reference spec.
// Establishing equivalence ensures that no mistakes are made in the optimizations made by the implementation.
contract MulticallerWithSenderSymTest is SymTest, Test {
    MulticallerWithSenderMock impl; // implementation
    MulticallerWithSenderSpec spec; // reference spec

    // Slot number of the `balanceOf` mapping in TargetMock.
    uint private constant _BALANCEOF_SLOT = 1;

    address[] targetMocks;

    function setUp() public {
        impl = new MulticallerWithSenderMock();
        spec = new MulticallerWithSenderSpec();

        assert(impl.sender() == spec.sender());
        assert(impl.reentrancyUnlocked() == spec.reentrancyUnlocked());

        vm.deal(address(this), 100_000_000 ether);
        vm.assume(address(impl).balance == address(spec).balance);
    }

    function _check_equivalence(bytes memory data) internal {
        uint value = svm.createUint256("value");

        (bool success_impl, bytes memory retdata_impl) = address(impl).call{value: value}(data);
        (bool success_spec, bytes memory retdata_spec) = address(spec).call{value: value}(data);

        // Check: `impl` succeeds if and only if `spec` succeeds.
        assert(success_impl == success_spec);
        // Check: the return data must be identical.
        assert(keccak256(retdata_impl) == keccak256(retdata_spec));

        // Check: the storage states must remain the same.
        assert(impl.sender() == spec.sender());
        assert(impl.reentrancyUnlocked() == spec.reentrancyUnlocked());

        // Check: the remaining balances must be equal.
        assert(address(impl).balance == address(spec).balance);
        // Check: the total amounts sent to each target must be equal.
        for (uint i = 0; i < targetMocks.length; i++) {
            bytes32 target_balance_impl = vm.load(targetMocks[i], keccak256(abi.encode(impl, _BALANCEOF_SLOT)));
            bytes32 target_balance_spec = vm.load(targetMocks[i], keccak256(abi.encode(spec, _BALANCEOF_SLOT)));
            assert(target_balance_impl == target_balance_spec);
        }
    }

    // Generate input arguments for `aggregateWithSender()`, given the specific sizes of dynamic arrays.
    function _create_inputs(
        uint targets_length,
        uint data_length,
        uint values_length,
        uint data_size
    ) internal returns (bytes memory) {
        // Construct `address[] targets` where `target[i]` may or may not be aliased with `target[i-1]`.
        // This results in 2^(n-1) combinations of `targets` arrays, covering various alias scenarios.
        address[] memory targets = new address[](targets_length);
        for (uint i = 0; i < targets_length; i++) {
            if (i == 0 || svm.createBool("unique_targets[i]")) {
                address targetMock = address(new TargetMock());
                targetMocks.push(targetMock);
                targets[i] = targetMock;
            } else {
                targets[i] = targets[i-1]; // alias
            }
        }

        // Construct `bytes[] data`, where `bytes data[i]` is created with the given `data_size`.
        bytes[] memory data = new bytes[](data_length);
        for (uint i = 0; i < data_length; i++) {
            data[i] = svm.createBytes(data_size, "data[i]");
        }

        // Construct `uint256[] values`.
        uint256[] memory values = new uint256[](values_length);
        for (uint i = 0; i < values_length; i++) {
            values[i] = svm.createUint256("values[i]");
        }

        return abi.encodeWithSelector(MulticallerWithSender.aggregateWithSender.selector, targets, data, values);
    }

    //
    // Instantiations of the `_check_equivalence()` test for various combinations of dynamic array sizes.
    //

    function check_fallback_0() public { _check_equivalence(""); }
    function check_fallback_1() public { _check_equivalence("1"); }

    function check_1_0_0_1()  public { _check_equivalence(_create_inputs(1, 0, 0, 1)); }
    function check_0_0_0_1()  public { _check_equivalence(_create_inputs(0, 0, 0, 1)); }
    function check_1_1_1_1()  public { _check_equivalence(_create_inputs(1, 1, 1, 1)); }
    function check_2_2_2_1()  public { _check_equivalence(_create_inputs(2, 2, 2, 1)); }

    function check_1_0_0_32() public { _check_equivalence(_create_inputs(1, 0, 0, 32)); }
    function check_0_0_0_32() public { _check_equivalence(_create_inputs(0, 0, 0, 32)); }
    function check_1_1_1_32() public { _check_equivalence(_create_inputs(1, 1, 1, 32)); }
    function check_2_2_2_32() public { _check_equivalence(_create_inputs(2, 2, 2, 32)); }

    function check_1_0_0_31() public { _check_equivalence(_create_inputs(1, 0, 0, 31)); }
    function check_0_0_0_31() public { _check_equivalence(_create_inputs(0, 0, 0, 31)); }
    function check_1_1_1_31() public { _check_equivalence(_create_inputs(1, 1, 1, 31)); }
    function check_2_2_2_31() public { _check_equivalence(_create_inputs(2, 2, 2, 31)); }

    function check_1_0_0_65() public { _check_equivalence(_create_inputs(1, 0, 0, 65)); }
    function check_0_0_0_65() public { _check_equivalence(_create_inputs(0, 0, 0, 65)); }
    function check_1_1_1_65() public { _check_equivalence(_create_inputs(1, 1, 1, 65)); }
    function check_2_2_2_65() public { _check_equivalence(_create_inputs(2, 2, 2, 65)); }
}
