// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.5.2;

contract OldCompilerTest {

    function check_assert(uint x) public pure {
        if (x == 0) return;
        assert(false); // old compiler versions don't revert with panic; instead, they run invalid opcode, which halmos ignores, resulting in no error here.
    }

    function check_myAssert(uint x) public pure {
        if (x == 0) return;
        myAssert(false); // you can use your own assertion that panic-reverts if assertion fails, when using halmos for old version code.
    }

    function myAssert(bool cond) internal pure {
        if (!cond) {
            assembly {
                mstore(0x00, 0x4e487b71)
                mstore(0x20, 0x01)
                revert(0x1c, 0x24)
            }
        }
    }

}
