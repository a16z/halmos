// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Context is Test {
    bool public flag;

    function call0(uint mode) external {
        flag = true;

        if (mode == 1) {
            assembly {
                stop()
            }
        } else if (mode == 2) {
            assembly {
                invalid()
            }
        } else if (mode == 3) {
            assembly {
                revert(0, 0)
            }
        } else if (mode == 4) {
            revert("blah"); // revert(Error("blah"))
        } else if (mode == 5) {
            assert(false); // revert(Panic(1))
        } else if (mode == 6) {
            assembly {
                return(0, 0)
            }
        } else if (mode == 7) {
            assembly {
                return(0, 32)
            }
        } else if (mode == 8) {
            assembly {
                let p := mload(0x40)
                returndatacopy(p, returndatasize(), 32) // OutOfBoundsRead
            }
        } else if (mode == 9) {
            vm.prank(address(0));
            vm.prank(address(0)); // HalmosException
        } else if (mode == 10) {
            fail();
        }
    }

    function call1(uint mode1, address ctx0, uint mode0) external returns (bool success, bytes memory retdata) {
        flag = true;

        (success, retdata) = ctx0.call(abi.encodeWithSelector(Context.call0.selector, mode0));

        if (mode1 == 0) {
            bytes memory result = abi.encode(success, retdata);
            assembly {
                revert(add(32, result), mload(result))
            }
        }
    }
}

contract ConstructorContext {
    constructor(Context ctx, uint mode, bool fail) {
        assert(returndatasize() == 0); // empty initial returndata
        assert(msg.data.length == 0); // no calldata for constructor

        ctx.call0(mode);

        if (fail) revert("fail");
    }

    function returndatasize() internal pure returns (uint size) {
        assembly {
            size := returndatasize()
        }
    }
}

contract ContextTest is Test {
    address internal testDeployer;
    address internal testAddress;

    Context internal ctx;

    constructor() payable {
        assertEq(returndatasize(), 0); // empty initial returndata
        assertEq(msg.data.length, 0); // no calldata for test constructor
        assertEq(msg.value, 0); // no callvalue
        testDeployer = msg.sender;
        testAddress = address(this);
    }

    function ensure_test_context() internal {
        assertEq(address(this), testAddress);
        assertEq(msg.sender, testDeployer);
        assertEq(msg.value, 0); // no callvalue
        assertGt(msg.data.length, 0); // non-empty calldata
    }

    function setUp() public payable {
        assertEq(returndatasize(), 0); // empty initial returndata
        ensure_test_context();

        ctx = new Context();

        assertEq(returndatasize(), 0); // empty returndata after create
    }

    function check_setup() public payable {
        assert(returndatasize() == 0); // empty initial returndata
        ensure_test_context();
    }

    function check_returndata() public payable {
        assert(returndatasize() == 0); // empty initial returndata
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 1));
        assert(returndatasize() == 0);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 2));
        assert(returndatasize() == 0);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 3));
        assert(returndatasize() == 0);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 4));
        assert(returndatasize() == 100);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 5));
        assert(returndatasize() == 36);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 6));
        assert(returndatasize() == 0);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 7));
        assert(returndatasize() == 32);
        ensure_test_context();

        address(ctx).call(abi.encodeWithSelector(Context.call0.selector, 8));
        assert(returndatasize() == 0);
        ensure_test_context();

        new Context();
        assert(returndatasize() == 0); // empty returndata after create
        ensure_test_context();
    }

    function check_create() public payable {
        assertEq(returndatasize(), 0); // empty initial returndata
        ensure_test_context();

        Context ctx1 = new Context();
        ConstructorContext cc1 = new ConstructorContext(ctx1, 7, false);
        cc1; // silence unused warning
        assertEq(returndatasize(), 0); // empty returndata after create
        ensure_test_context();

        assert(ctx1.flag()); // do not use assertTrue() as it updates returndatasize()
        assertEq(returndatasize(), 32);
        ensure_test_context();

        Context ctx2 = new Context();
        try new ConstructorContext(ctx2, 7, true) returns (ConstructorContext cc2) {
            cc2; // silence unused warning
        } catch {}
        assertEq(returndatasize(), 100); // returndata for create failure
        ensure_test_context();

        assert(!ctx2.flag()); // do not use assertFalse() as it updates returndatasize()
        assertEq(returndatasize(), 32);
        ensure_test_context();
    }

    function check_create_halmos_exception() public payable {
        assert(returndatasize() == 0); // empty initial returndata
        ensure_test_context();

        try new ConstructorContext(ctx, 9, false) returns (ConstructorContext cc) {
            cc; // silence unused warning
        } catch {}

        assert(false); // shouldn't reach here
    }

    function check_call0_normal(uint mode0) public payable {
        // vm.assume(mode0 < 9);
        // NOTE: explicitly branch over mode0, as an infeasible path with mode0 >= 9 may not be eliminated due to an extremely inefficient solver environment (e.g, github workflow)
        mode0 = split_mode_up_to_9(mode0);

        _check_call0(mode0);
    }

    function check_call0_halmos_exception() public payable {
        _check_call0(9);
    }

    function check_call0_fail() public payable {
        _check_call0(10);
    }

    function _check_call0(uint mode0) public payable {
        assert(returndatasize() == 0); // empty initial returndata
        ensure_test_context();

        Context ctx0 = ctx;

        (bool success0, bytes memory retdata0) = address(ctx0).call(abi.encodeWithSelector(Context.call0.selector, mode0));
        assert(returndatasize() == retdata0.length);
        ensure_test_context();

        ensure_call0_result(mode0, success0, retdata0);

        assert(ctx0.flag() == success0); // revert state
        assert(returndatasize() == 32);
        ensure_test_context();
    }

    function check_call1_normal(uint mode1, uint mode0) public payable {
        // vm.assume(mode0 < 9);
        // NOTE: explicitly branch over mode0, as an infeasible path with mode0 >= 9 may not be eliminated due to an extremely inefficient solver environment (e.g, github workflow)
        mode0 = split_mode_up_to_9(mode0);

        _check_call1(mode1, mode0);
    }

    function check_call1_halmos_exception(uint mode1) public payable {
        _check_call1(mode1, 9);
    }

    function check_call1_fail(uint mode1) public payable {
        _check_call1(mode1, 10);
    }

    function _check_call1(uint mode1, uint mode0) public payable {
        assert(returndatasize() == 0); // empty initial returndata
        ensure_test_context();

        Context ctx1 = new Context();
        Context ctx0 = ctx;

        (bool success1, bytes memory retdata1) = address(ctx1).call(abi.encodeWithSelector(Context.call1.selector, mode1, ctx0, mode0));
        assert(returndatasize() == retdata1.length);
        ensure_test_context();

        assert(success1 == (mode1 > 0));
        (bool success0, bytes memory retdata0) = abi.decode(retdata1, (bool, bytes));
        ensure_test_context();

        ensure_call0_result(mode0, success0, retdata0);

        // revert state
        assert(ctx1.flag() == success1);
        assert(returndatasize() == 32);
        ensure_test_context();

        assert(ctx0.flag() == (success1 && success0));
        assert(returndatasize() == 32);
        ensure_test_context();
    }

    function ensure_call0_result(uint mode, bool success, bytes memory retdata) internal {
             if (mode ==  1) assert( success && retdata.length ==  0);
        else if (mode ==  2) assert(!success && retdata.length ==  0);
        else if (mode ==  3) assert(!success && retdata.length ==  0);
        else if (mode ==  4) assert(!success && retdata.length >   0);
        else if (mode ==  5) assert(!success && retdata.length == 36);
        else if (mode ==  6) assert( success && retdata.length ==  0);
        else if (mode ==  7) assert( success && retdata.length == 32);
        else if (mode ==  8) assert(!success && retdata.length ==  0);
        else if (mode ==  9) assert(!success && retdata.length ==  0);
        else if (mode == 10) assert(!success && retdata.length ==  0);
    }

    function split_mode_up_to_9(uint mode) internal returns (uint) {
             if (mode == 0) return 0;
        else if (mode == 1) return 1;
        else if (mode == 2) return 2;
        else if (mode == 3) return 3;
        else if (mode == 4) return 4;
        else if (mode == 5) return 5;
        else if (mode == 6) return 6;
        else if (mode == 7) return 7;
        else if (mode == 8) return 8;
        else                return 0;
    }

    function returndatasize() internal pure returns (uint size) {
        assembly {
            size := returndatasize()
        }
    }
}
