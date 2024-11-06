// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract Beep {
    function boop() public pure returns (uint256) {
        return 42;
    }
}

contract HalmosCheatCodeTest is SymTest, Test {
    function check_createUint() public {
        uint x = svm.createUint(256, 'x');
        uint y = svm.createUint(160, 'y');
        uint z = svm.createUint(8, 'z');
        assert(0 <= x && x <= type(uint256).max);
        assert(0 <= y && y <= type(uint160).max);
        assert(0 <= z && z <= type(uint8).max);
    }

    function check_createInt() public {
        int x = svm.createInt(256, 'x');
        int y = svm.createInt(160, 'y');
        int z = svm.createInt(8, 'z');
        assert(type(int256).min <= x && x <= type(int256).max);
        assert(type(int160).min <= y && y <= type(int160).max);
        assert(type(int8).min <= z && z <= type(int8).max);
    }

    function check_createBytes() public {
        bytes memory data = svm.createBytes(2, 'data');
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(0 <= x && x <= type(uint8).max);
        assert(0 <= y && y <= type(uint8).max);
    }

    function check_createString() public {
        string memory data = svm.createString(5, 'str');
        assert(bytes(data).length == 5);
    }

    function check_createUint256() public {
        uint x = svm.createUint256('x');
        assert(0 <= x && x <= type(uint256).max);
    }

    function check_createInt256() public {
        int x = svm.createInt256('x');
        assert(type(int256).min <= x && x <= type(int256).max);
    }

    function check_createBytes32() public {
        bytes32 x = svm.createBytes32('x');
        assert(0 <= uint(x) && uint(x) <= type(uint256).max);
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint256).max);
    }

    function check_createBytes4_basic() public {
        bytes4 x = svm.createBytes4('x');

        uint256 r;
        assembly {
            r := returndatasize()
        }
        assert(r == 32);

        uint256 x_uint = uint256(uint32(x));
        assertLe(x_uint, type(uint32).max);
        uint y; assembly { y := x }
        assertLe(y, type(uint256).max);
    }

    /// @dev we expect a counterexample
    ///      (meaning that createBytes4 is able to find the selector for boop())
    function check_createBytes4_finds_selector() public {
        Beep beep = new Beep();

        bytes4 selector = svm.createBytes4("selector");
        (bool succ, bytes memory ret) = address(beep).call(abi.encode(selector));
        vm.assume(succ);
        uint256 val = abi.decode(ret, (uint256));

        assertNotEq(val, 42);
    }


    function check_createAddress() public {
        address x = svm.createAddress('x');
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint160).max);
    }

    function check_createBool() public {
        bool x = svm.createBool('x');
        uint y; assembly { y := x }
        assert(y == 0 || y == 1);
    }

    function check_SymbolLabel() public returns (uint256) {
        uint x = svm.createUint256('');
        uint y = svm.createUint256(' ');
        uint z = svm.createUint256(' a ');
        uint w = svm.createUint256(' a b ');
        return x + y + z + w;
    }

    function check_FailUnknownCheatcode() public {
        // expected to fail with unknown cheatcode
        address(svm).call(abi.encodeWithSelector(Dummy.foo.selector));

        // NOTE: the following reverts due to the failure of the nonzero check for extcodesize(svm)
        // Dummy(address(svm)).foo();
    }

    function check_enableSymbolicStorage_pass(uint val) public {
        address dummy = address(new Beep());
        // initial value is zero
        assertEq(vm.load(dummy, bytes32(0)), 0);

        vm.store(dummy, bytes32(0), bytes32(val));
        svm.enableSymbolicStorage(dummy);
        // enableSymbolicStorage updates only uninitialized slots
        assertEq(vm.load(dummy, bytes32(0)), bytes32(val));
    }

    function check_enableSymbolicStorage_fail() public {
        address dummy = address(new Beep());
        svm.enableSymbolicStorage(dummy);
        // storage slots have been initialized with a symbolic value
        assertEq(vm.load(dummy, bytes32(0)), 0); // fail
    }

    function check_enableSymbolicStorage_nonexistent() public {
        // symbolic storage is not allowed for a nonexistent account
        svm.enableSymbolicStorage(address(0xdeadbeef)); // HalmosException
    }

    /// @custom:halmos --array-lengths name=1
    function check_extract_string_argument_fail(string memory name) public {
        uint x = svm.createUint256(name);
        console.log(x);
        assert(true);
    }
}

/// @custom:halmos --default-bytes-lengths 0,65
contract HalmosCreateCalldataTest is SymTest, Test {
    function check_createCalldata_Beep_1_excluding_pure() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Beep");
        _check_createCalldata_Beep(data); // fail because the only function in Beep is pure, which is excluded in createCalldata()
    }

    function check_createCalldata_Beep_1_including_pure() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Beep", true);
        _check_createCalldata_Beep(data);
    }

    function check_createCalldata_Beep_2_excluding_pure() public {
        bytes memory data = svm.createCalldata("Beep");
        _check_createCalldata_Beep(data); // fail because the only function in Beep is pure, which is excluded in createCalldata()
    }

    function check_createCalldata_Beep_2_including_pure() public {
        bytes memory data = svm.createCalldata("Beep", true);
        _check_createCalldata_Beep(data);
    }

    function _check_createCalldata_Beep(bytes memory data) public {
        Beep beep = new Beep();
        (bool success, bytes memory retdata) = address(beep).call(data);
        vm.assume(success);
        uint ret = abi.decode(retdata, (uint256));
        assertEq(ret, 42);
    }

    function check_createCalldata_Mock_1_pass() public {
        bytes memory data = svm.createCalldata("Mock");
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_1_fail() public {
        bytes memory data = svm.createCalldata("Mock");
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_2_excluding_view_pass() public {
        bytes memory data = svm.createCalldata("Mock", false);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_2_excluding_view_fail() public {
        bytes memory data = svm.createCalldata("Mock", false);
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_2_including_view_pass() public {
        bytes memory data = svm.createCalldata("Mock", true);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_2_including_view_fail() public {
        bytes memory data = svm.createCalldata("Mock", true);
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_3_pass() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock");
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_3_fail() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock");
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_4_excluding_view_pass() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock", false);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_4_excluding_view_fail() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock", false);
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_4_including_view_pass() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock", true);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_4_including_view_fail() public {
        bytes memory data = svm.createCalldata("HalmosCheatCode.t.sol", "Mock", true);
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_interface_excluding_view_pass() public {
        bytes memory data = svm.createCalldata("IMock");
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_interface_excluding_view_fail() public {
        bytes memory data = svm.createCalldata("IMock");
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_interface_including_view_pass() public {
        bytes memory data = svm.createCalldata("IMock", true);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_interface_including_view_fail() public {
        bytes memory data = svm.createCalldata("IMock", true);
        _check_createCalldata_Mock(data, false);
    }

    function _check_createCalldata_Mock(bytes memory data, bool pass) public {
        Mock target = new Mock(false); // use Mock(true) for debugging
        _check_createCalldata_generic(address(target), data, pass);
    }

    function _check_createCalldata_generic(address target, bytes memory data, bool pass) public {
        (bool success, bytes memory retdata) = target.call(data);
        vm.assume(success);

        bytes4 ret = abi.decode(retdata, (bytes4));
        bytes4 expected = bytes4(bytes.concat(data[0], data[1], data[2], data[3]));

        if (pass) {
            assertEq(ret, expected);
        } else {
            // NOTE: the purpose of fail mode is to count the number of calldata combinations,
            // where the number of calldata combinations is equal to the # of counterexamples.
            assertNotEq(ret, expected);
        }
    }

    function check_createCalldata_NestedArrays_1_pass() public {
        bytes memory data = svm.createCalldata("NestedArrays");
        _check_createCalldata_NestedArrays(data, true);
    }

    function check_createCalldata_NestedArrays_1_fail() public {
        bytes memory data = svm.createCalldata("NestedArrays");
        _check_createCalldata_NestedArrays(data, false);
    }

    function _check_createCalldata_NestedArrays(bytes memory data, bool pass) public {
        NestedArrays target = new NestedArrays(false); // use NestedArrays(true) for debugging
        _check_createCalldata_generic(address(target), data, pass);
    }

    function check_createCalldata_Dummy_fail() public {
        // fail due to ambiguity of Dummy
        bytes memory data = svm.createCalldata("Dummy");
    }

    function check_createCalldata_Fallback() public {
        Fallback fb = new Fallback();
        bytes memory data = svm.createCalldata("Fallback");
        (bool success, bytes memory retdata) = address(fb).call(data);

        assertTrue(success);
        assertEq(retdata, data);
    }
}

contract Fallback {
//  fallback() external payable { }
    fallback(bytes calldata input) external payable returns (bytes memory output) {
        console.log("fallback");
        console.log(input.length);
        output = input;
    }

    receive() external payable {
        console.log("receive");
    }
}

contract Mock {
    bool log;

    constructor (bool _log) {
        log = _log;
    }

    function f_pure() public pure returns (bytes4) {
        return this.f_pure.selector;
    }

    function f_view() public view returns (bytes4) {
        return this.f_view.selector;
    }

    function foo(uint[] memory x) public returns (bytes4) {
        if (log) {
            console.log("foo(uint[])");
            console.log(x.length); // 0, 1, 2
        }
        return this.foo.selector;
    }

    function bar(bytes memory x) public returns (bytes4) {
        if (log) {
            console.log("bar(bytes)");
            console.log(x.length); // 0, 65
        }
        return this.bar.selector;
    }

    function zoo(uint[] memory x, bytes memory y) public returns (bytes4) {
        if (log) {
            console.log("zoo(uint[],bytes)");
            // 6 (= 3 * 2) combinations
            console.log(x.length); // 0, 1, 2
            console.log(y.length); // 0, 65
        }
        return this.zoo.selector;
    }

    function foobar(bytes[] memory x) public returns (bytes4) {
        if (log) {
            console.log("foobar(bytes[])");
            console.log(x.length); // 0, 1, 2
            // 7 (= 1 + 2 + 2*2) combinations
            for (uint i = 0; i < x.length; i++) {
                console.log(x[i].length); // 0, 65
            }
        }
        return this.foobar.selector;
    }
}

contract NestedArrays {
    bool log;

    constructor (bool _log) {
        log = _log;
    }

    struct BytesBytes {
        bytes b1;
        bytes b2;
    }

    struct UintBytesBytesArray {
        uint256 u1;
        BytesBytes[] u2;
    }

    struct UintBytesArray {
        uint256 u1;
        bytes[] u2;
    }

    function f_bytes_bytes_array(BytesBytes[] memory x) public returns (bytes4) {
        if (log) {
            console.log("f((bytes,bytes)[])");
            console.log(x.length); // 0, 1, 2
            // 21 (= 1 + 4 + 4*4) combinations
            for (uint i = 0; i < x.length; i++) {
                // 4 (= 2*2) combinations
                console.log(x[i].b1.length); // 0, 65
                console.log(x[i].b2.length); // 0, 65
            }
        }
        return this.f_bytes_bytes_array.selector;
    }

    function f_bytes_bytes_array_array(UintBytesBytesArray[] memory x) public returns (bytes4) {
        if (log) {
            console.log("f((uint256,(bytes,bytes)[])[])");
            console.log(x.length); // 0, 1, 2
            // 463 (= 1 + 21 + 21*21) combinations
            for (uint i = 0; i < x.length; i++) {
                // 21 (= 1 + 4 + 4*4) combinations
                console.log(x[i].u2.length); // 0, 1, 2
                for (uint j = 0; j < x[i].u2.length; j++) {
                    // 4 (= 2*2) combinations
                    console.log(x[i].u2[j].b1.length); // 0, 65
                    console.log(x[i].u2[j].b2.length); // 0, 65
                }
            }
        }
        return this.f_bytes_bytes_array_array.selector;
    }

    function f_bytes_array_array(UintBytesArray[] memory x) public returns (bytes4) {
        if (log) {
            console.log("f((uint256,bytes[])[])");
            console.log(x.length); // 0, 1, 2
            // 57 (= 1 + 7 + 7*7) combinations
            for (uint i = 0; i < x.length; i++) {
                // 7 (= 1 + 2 + 2*2) combinations
                console.log(x[i].u2.length); // 0, 1, 2
                for (uint j = 0; j < x[i].u2.length; j++) {
                    // 2 combinations
                    console.log(x[i].u2[j].length);  // 0, 65
                }
            }
        }
        return this.f_bytes_array_array.selector;
    }
}

interface IMock {
    function f_pure() external pure returns (bytes4);

    function f_view() external view returns (bytes4);

    function foo(uint[] calldata x) external returns (bytes4);

    function bar(bytes calldata x) external returns (bytes4);

    function zoo(uint[] calldata x, bytes calldata y) external returns (bytes4);

    function foobar(bytes[] calldata x) external returns (bytes4);
}

interface Dummy {
    function foo() external;
}
