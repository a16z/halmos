// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// a16z/halmos#579: the optimizer (notably via-IR) may constant-fold the keccak of a
// storage slot into a PUSH32 literal, e.g. in a constructor, while the runtime code
// computes the same slot with SHA3. Both accesses must hit the same storage cell.
// The literal slots below are written with inline assembly to emulate that folding.
contract PrecomputedSlots {
    struct S {
        uint256 a;
        uint256 b;
    }

    mapping(uint256 => uint256) public m; // slot 0
    mapping(uint256 => S) public ms; // slot 1
    mapping(uint256 => mapping(uint256 => uint256)) public mm; // slot 2

    constructor() {
        assembly {
            // m[76] = 890: keccak256(abi.encode(76, 0))
            sstore(0xfec8fc345c07e1cb780845776a87475444a9ad5d006d1c0ba391a7299932fc3d, 890)
            // ms[76].b = 7: keccak256(abi.encode(76, 1)) + 1
            sstore(0x1ed6ba569b422e6ce8625b852f3078402250527a73572e6a816cf9263aceeba2, 7)
            // mm[76][5] = 42: keccak256(abi.encode(5, keccak256(abi.encode(76, 2))))
            sstore(0x9da36e986660358a9db129a989c5480cefb4582a99ba5113d8d083b4a63c69d7, 42)
        }
    }

    function incr() external {
        m[76] += 1;
    }
}

contract PrecomputedSlotsTest {
    PrecomputedSlots c;

    function setUp() public {
        c = new PrecomputedSlots();
    }

    function check_mapping_literal_slot() public view {
        assert(c.m(76) == 890);
    }

    function check_struct_field_literal_slot() public view {
        (uint256 a, uint256 b) = c.ms(76);
        assert(a == 0);
        assert(b == 7);
    }

    function check_nested_mapping_literal_slot() public view {
        assert(c.mm(76, 5) == 42);
    }

    function check_write_after_literal_slot() public {
        c.incr();
        c.incr();
        assert(c.m(76) == 892);
    }
}
