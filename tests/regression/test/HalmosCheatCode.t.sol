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

    function check_randomUint() public {
        uint x = vm.randomUint(256);
        uint y = vm.randomUint(160);
        uint z = vm.randomUint(8);
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

    function check_randomInt() public {
        int x = vm.randomInt(256);
        int y = vm.randomInt(160);
        int z = vm.randomInt(8);
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

    function check_randomBytes() public {
        bytes memory data = vm.randomBytes(2);
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(0 <= x && x <= type(uint8).max);
        assert(0 <= y && y <= type(uint8).max);
    }


    function check_createBytes_empty() public {
        bytes memory data = svm.createBytes(0, 'data');
        assert(data.length == 0);
    }

    function check_randomBytes_empty() public {
        bytes memory data = vm.randomBytes(0);
        assert(data.length == 0);
    }

    function check_createString() public {
        string memory data = svm.createString(5, 'str');
        assert(bytes(data).length == 5);
    }

    function check_createString_empty() public {
        string memory data = svm.createString(0, 'str');
        assert(bytes(data).length == 0);
    }

    function check_createUint256() public {
        uint x = svm.createUint256('x');
        assert(0 <= x && x <= type(uint256).max);
    }

    function check_randomUint256() public {
        uint x = vm.randomUint();
        assert(0 <= x && x <= type(uint256).max);
    }

    function check_createInt256() public {
        int x = svm.createInt256('x');
        assert(type(int256).min <= x && x <= type(int256).max);
    }

    function check_randomInt256() public {
        int x = vm.randomInt();
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
    }


    function check_randomBytes4() public {
        bytes4 x = vm.randomBytes4();

        uint256 r;
        assembly {
            r := returndatasize()
        }
        assert(r == 32);

        uint256 x_uint = uint256(uint32(x));
        assertLe(x_uint, type(uint32).max);
    }

    function check_randomBytes8() public {
        bytes8 x = vm.randomBytes8();

        uint256 r;
        assembly {
            r := returndatasize()
        }
        assert(r == 32);

        uint256 x_uint = uint256(uint64(x));
        assertLe(x_uint, type(uint64).max);
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

    function check_randomAddress() public {
        address x = vm.randomAddress();
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint160).max);
    }

    function check_createBool() public {
        bool x = svm.createBool('x');
        uint y; assembly { y := x }
        assert(y == 0 || y == 1);
    }

    function check_randomBool() public {
        bool x = vm.randomBool();
        uint y; assembly { y := x }
        assert(y == 0 || y == 1);
    }

    function check_random_uint_range_concrete_pass() public {
        uint256 min = 120;
        uint256 max = 1_000_000;
        uint256 rand = vm.randomUint(min, max);
        assertGe(rand, min);
        assertLe(rand, max);
    }

    function check_random_uint_range_symbolic_fail(uint256 min, uint256 max) public {
        // expected to fail with HalmosException
        vm.randomUint(min, max);
    }

    function check_random_uint_range_max_greaterthan_min_fail() public {
        // expected to fail with HalmosException
        vm.randomUint(1, 0);
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

    function check_setArbitraryStorage_pass(uint val) public {
        address dummy = address(new Beep());
        // initial value is zero
        assertEq(vm.load(dummy, bytes32(0)), 0);

        vm.store(dummy, bytes32(0), bytes32(val));
        vm.setArbitraryStorage(dummy);
        // setArbitraryStorage updates only uninitialized slots
        assertEq(vm.load(dummy, bytes32(0)), bytes32(val));
    }

    function check_enableSymbolicStorage_fail() public {
        address dummy = address(new Beep());
        svm.enableSymbolicStorage(dummy);
        // storage slots have been initialized with a symbolic value
        assertEq(vm.load(dummy, bytes32(0)), 0); // fail
    }

    function check_setArbitraryStorage_fail() public {
        address dummy = address(new Beep());
        vm.setArbitraryStorage(dummy);
        // storage slots have been initialized with a symbolic value
        assertEq(vm.load(dummy, bytes32(0)), 0); // fail
    }


    function check_enableSymbolicStorage_nonexistent() public {
        // symbolic storage is not allowed for a nonexistent account
        svm.enableSymbolicStorage(address(0xdeadbeef)); // HalmosException
    }

    function check_setArbitraryStorage_nonexistent() public {
        // Arbitrary Storage is not allowed for a nonexistent account
        vm.setArbitraryStorage(address(0xdeadbeef)); // HalmosException
    }

    /// @custom:halmos --array-lengths name=1
    function check_extract_string_argument_fail(string memory name) public {
        uint x = svm.createUint256(name);
        console.log(x);
        assert(true);
    }

    function check_unsupported_cheatcode_fail() public {
        // expected to fail with unknown cheatcode
        vm.expectRevert("will revert");
    }

    function check_env_missing_fail() public {
        // expected to fail with ValueError
        int x = vm.envInt("MISSING_FROM_DOTENV");
        assertEq(x, 42);
    }

    function check_env_int() public {
        int x = vm.envInt("API");
        assertEq(x, 10);
    }
    function check_env_bytes32() public {
        bytes32  x = vm.envBytes32("Byte32_val");
        assertEq(x, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    }

    function check_env_address() public {
        address x = vm.envAddress("ADDRESS");
        assertEq(x, address(0xdeadbeef));
    }

    function check_env_bool() public {
        bool x = vm.envBool("BOOL");
        assertEq(x, true);
    }

    function check_env_uint() public {
        uint x = vm.envUint("UINT");
        assertEq(x, 2**256 - 1);
    }

    function check_env_bytes() public {
        bytes memory x = vm.envBytes("BYTES");
        assertEq(x, hex"deadbeef");
    }

    function check_env_string() public {
        string memory x = vm.envString("STRING");
        assertEq(x, "hello world");
    }

    function check_env_int_array() public {
        int[] memory x = vm.envInt("INT_ARRAY", ",");
        int y = 1;
        assertEq(x.length, 4);
        assertEq(x[0], 1);
        assertEq(x[1], -1);
        assertEq(x[2], 4);
        assertEq(x[3], 5);
    }

    function check_env_address_array() public {
        address[] memory x = vm.envAddress("ADDRESS_ARRAY", ",");
        assertEq(x.length, 2);
        assertEq(x[0], address(0x00000000000000000000000000000000DeaDBeef));
        assertEq(x[1], address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE));
    }

    function check_env_bool_array() public {
        bool[] memory x = vm.envBool("BOOL_ARRAY", ",");
        assertEq(x.length, 2);
        assertEq(x[0], true);
        assertEq(x[1], false);
    }

    function check_env_bytes32_array() public {
        bytes32[] memory x = vm.envBytes32("BYTES32_ARRAY", ",");
        assertEq(x.length, 2);
        assertEq(x[0], 0x00000000000000000000000000000000000000000000000000000000DeaDBeef);
        assertEq(x[1], 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    }

    function check_env_string_array() public {
        string[] memory x = vm.envString("STRING_ARRAY", ",");
        assertEq(x.length, 3);
        assertEq(x[0], "hello");
        assertEq(x[1], "world");
        assertEq(x[2], "This string is definitely longer than thirty-one bytes!");
    }

    function check_env_uint_array() public {
        uint[] memory x = vm.envUint("UINT_ARRAY", ",");
        assertEq(x.length, 3);
        assertEq(x[0], 1);
        assertEq(x[1], 2);
        assertEq(x[2], 3);
    }

    function check_env_bytes_array() public {
        bytes[] memory x = vm.envBytes("BYTES_ARRAY", ",");
        assertEq(x.length, 4);
        assertEq(x[0], hex"DeaDBeef");
        assertEq(x[1], hex"00000000000000000000000000000000DeaDBeef");
        assertEq(x[2], hex"00000000000000000000000000000000000000000000000000000000DeaDBeef");
        assertEq(x[3], hex"00000000000000000000000000000000000000000000000000000000DeaDBeefDeaDBeef");

    }

    function check_env_or_address() public {
        address x = vm.envOr("ADDRESS", address(0xdead));
        assertEq(x, address(0xdeadbeef));
    }

    function check_env_or_address_without_env_var() public {
        address x = vm.envOr("MISSING", address(0xdeadbeef));
        assertEq(x, address(0xdeadbeef));
    }

    function check_env_or_bool() public {
        bool x = vm.envOr("BOOL", false);
        assertEq(x, true);
    }

    function check_env_or_bool_without_env_var(bool x) public {
        assertEq(vm.envOr("MISSING", true), true);
        assertEq(vm.envOr("MISSING", false), false);
        assertEq(vm.envOr("MISSING", x), x);
    }

    function check_env_or_bytes() public {
        bytes memory y = hex"abcd";
        bytes memory x = vm.envOr("BYTES_ENV_OR", y);
        assertEq(x, hex"00000000000000000000000000000000000000000000000000000000DeaDBeefDeaDBeef");
    }

    function check_env_or_bytes_without_env_var() public {
        bytes memory y = hex"abcd";
        bytes memory x = vm.envOr("MISSING", y);
        assertEq(x, y);
    }


    function check_env_or_string() public {
        string memory y = " hello ";
        string memory x = vm.envOr("STRING_ENV_OR", y);
        assertEq(x, "This string is definitely longer than thirty-one bytes!");
    }

     function check_env_or_string_without_env_var() public {
        string memory y = "Beep boop scabadeepdap dooweep woop woop hewooo!";
        string memory x = vm.envOr("MISSING", y);
        assertEq(x, y);
    }


    function check_env_or_bytes32() public {
        bytes32 y = 0xDDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDD;
        bytes32 x = vm.envOr("BYTES32_ENV_OR", y);
        assertEq(x, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    }

    function check_env_or_bytes32_without_env_var() public {
        bytes32 y = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        bytes32 x = vm.envOr("BYTES32", y);
        assertEq(x, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    }

    function check_env_or_int(int z) public {
        assertEq(vm.envOr("INT_ENV_OR", -10), type(int).max);
        assertEq(vm.envOr("MISSING_ENV_VAR", type(int).min), type(int).min);
        assertEq(vm.envOr("MISSING_ENV_VAR", z), z);
    }

    function check_env_or_uint(uint z) public {
        assertEq(vm.envOr("UINT_ENV_OR", uint256(1)), 1234);
        assertEq(vm.envOr("UINT_ENV_OR", type(uint256).max), 1234);
        assertEq(vm.envOr("MISSING_ENV_VAR", uint256(42)), 42);
        assertEq(vm.envOr("MISSING_ENV_VAR", z), z);
    }

    function check_env_or_address_array() public {
        address[] memory x = new address[](0);
        address[] memory y = vm.envOr("ADDRESS_ARRAY", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], address(0xdeadbeef));
        assertEq(y[1], 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    }

    function check_env_or_address_array_without_env_var() public {
        address[] memory x = new address[](1);
        x[0] = address(0xaabbccdd);
        address[] memory y = vm.envOr("MISSING", ",", x);
        assertEq(y.length, 1);
        assertEq(y[0], x[0]);
    }

    function check_env_or_bool_array() public {
        bool[] memory x = new bool[](2);
        x[0] = false;
        x[1] = true;
        bool[] memory y = vm.envOr("BOOL_ARRAY", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], true);
        assertEq(y[1], false);
    }

    function check_env_or_bool_array_without_env_var() public {
        bool[] memory x = new bool[](3);
        x[0] = true;
        x[1] = false;
        x[2] = true;
        bool[] memory y = vm.envOr("MISSING", ",", x);
        assertEq(y.length, 3);
        assertEq(y[0], x[0]);
        assertEq(y[1], x[1]);
        assertEq(y[2], x[2]);
    }

    function check_env_or_bytes32_array() public {
        bytes32[] memory x = new bytes32[](2);
        x[0] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        x[1] = 0x00000000000000000000000000000000000000000000000000000000DeaDBeef;
        bytes32[] memory y = vm.envOr("BYTES32_ARRAY_ENV_OR", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 0x00000000000000000000000000000000000000000000000000000000DeaDBeef);
        assertEq(y[1], 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);

    }

    function check_env_or_bytes32_array_without_env_var() public {
        bytes32[] memory x = new bytes32[](2);
        x[0] = 0x00000000000000000000000000000000000000000000000000000000DeaDBeef;
        x[1] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        bytes32[] memory y = vm.envOr("BYTES32_ARRAY2", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 0x00000000000000000000000000000000000000000000000000000000DeaDBeef);
        assertEq(y[1], 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);

    }

    function check_env_or_int_array() public {
        int[] memory x = new int[](2);
        x[0] = 1;
        x[1] = -1;
        int[] memory y = vm.envOr("INT_ARRAY_ENV_OR", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 57896044618658097711785492504343953926634992332820282019728792003956564819967);
        assertEq(y[1], -57896044618658097711785492504343953926634992332820282019728792003956564819967);
    }

    function check_env_or_int_array_without_env_var() public {
        int[] memory x = new int[](2);
        x[0] = 1;
        x[1] = -1;
        int[] memory y = vm.envOr("MISSING", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 1);
        assertEq(y[1], -1);
    }


    function check_env_or_uint_array() public {
        uint[] memory x = new uint[](2);
        x[0] = 1;
        x[1] = 3;
        uint[] memory y = vm.envOr("UINT_ARRAY_ENV_OR", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 115792089237316195423570985008687907853269984665640564039457584007913129639935);
        assertEq(y[1], 0);
    }

    function check_env_or_uint_array_without_env_var() public {
        uint[] memory x = new uint[](2);
        x[0] = 1;
        x[1] = 3;
        uint[] memory y = vm.envOr("MISSING", ",", x);
        assertEq(y.length, 2);
        assertEq(y[0], 1);
        assertEq(y[1], 3);
    }

    function check_env_or_bytes_array() public {
        bytes[] memory bytes_lst = new bytes[](3);
        bytes_lst[0] =  hex"DeaDBeef";
        bytes_lst[1] =  hex"DeaDBeef";
        bytes_lst[2] =  hex"ff";
        bytes[] memory return_bytes_lst = vm.envOr("BYTES_ARRAY_ENV_OR",",",bytes_lst);
        assertEq(return_bytes_lst.length, 3);
        assertEq(return_bytes_lst[0], hex"00000000000000000000000000000000000000000000000000000000DeaDBeef");
        assertEq(return_bytes_lst[1], hex"DeaDBeef");
        assertEq(return_bytes_lst[2], hex"00000000000000000000000000000000000000000000000000000000DeaDBeefDeaDBeef");
    }

    function check_env_or_bytes_array_without_env_var() public {
        bytes[] memory bytes_lst = new bytes[](3);
        bytes_lst[0] =  hex"ab";
        bytes_lst[1] =  hex"";
        bytes_lst[2] =  hex"00000000000000000000000000000000000000000000000000000000DeaDBeefDeaDBeef";
        bytes[] memory return_bytes_lst = vm.envOr("MISSING",",",bytes_lst);
        assertEq(return_bytes_lst.length, 3);
        assertEq(return_bytes_lst[0], bytes_lst[0]);
        assertEq(return_bytes_lst[1], bytes_lst[1]);
        assertEq(return_bytes_lst[2], bytes_lst[2]);
    }

    function check_env_or_string_array() public {
        string[] memory string_lst = new string[](3);
        string_lst[0] =  " ";
        string_lst[1] =  " ";
        string_lst[2] =  " ";
        string[] memory return_string_lst = vm.envOr("STRING_ARRAY",",",string_lst);
        assertEq(return_string_lst.length, 3);
        assertEq(return_string_lst[0], "hello");
        assertEq(return_string_lst[1], "world");
        assertEq(return_string_lst[2], "This string is definitely longer than thirty-one bytes!");
    }

    function check_env_or_string_array_without_env_var() public {
        string[] memory string_lst = new string[](3);
        string_lst[0] =  "some short string";
        string_lst[1] =  "";
        string_lst[2] =  "This string is definitely longer than thirty-one bytes!";
        string[] memory return_string_lst = vm.envOr("MISSING",",",string_lst);
        assertEq(return_string_lst.length, 3);
        assertEq(return_string_lst[0], string_lst[0]);
        assertEq(return_string_lst[1], string_lst[1]);
        assertEq(return_string_lst[2], string_lst[2]);
    }

    function check_env_exists() public {
        assertEq(vm.envExists("KEY"), true);
        assertEq(vm.envExists("nonexistent"), false);
    }
}

/// @custom:halmos --default-bytes-lengths 0,65
contract HalmosCreateCalldataTest is SymTest, Test {
    Beep beep = new Beep();
    Mock mock = new Mock(false); // use Mock(true) for debugging

    function check_createCalldata_unknown_fail() public {
        // fail because 0xbeef is not a contract account
        bytes memory data = svm.createCalldata(address(0xbeef));
    }

    function check_createCalldata_Beep_0_excluding_pure() public {
        bytes memory data = svm.createCalldata(address(beep));
        _check_createCalldata_Beep(data); // fail because the only function in Beep is pure, which is excluded in createCalldata()
    }

    function check_createCalldata_Beep_0_including_pure() public {
        bytes memory data = svm.createCalldata(address(beep), true);
        _check_createCalldata_Beep(data);
    }

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
        (bool success, bytes memory retdata) = address(beep).call(data);
        vm.assume(success);
        uint ret = abi.decode(retdata, (uint256));
        assertEq(ret, 42);
    }

    function check_createCalldata_Mock_0_excluding_view_pass() public {
        bytes memory data = svm.createCalldata(address(mock));
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_0_excluding_view_fail() public {
        bytes memory data = svm.createCalldata(address(mock));
        _check_createCalldata_Mock(data, false);
    }

    function check_createCalldata_Mock_0_including_view_pass() public {
        bytes memory data = svm.createCalldata(address(mock), true);
        _check_createCalldata_Mock(data, true);
    }
    function check_createCalldata_Mock_0_including_view_fail() public {
        bytes memory data = svm.createCalldata(address(mock), true);
        _check_createCalldata_Mock(data, false);
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
        _check_createCalldata_generic(address(mock), data, pass);
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
