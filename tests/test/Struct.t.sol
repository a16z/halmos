// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/// @custom:halmos --solver-timeout-assertion 0
contract StructTest {
    struct Point {
        uint x;
        uint y;
    }

    function check_Struct(Point memory p) public pure returns (uint result) {
        unchecked {
            result += p.x + p.y;
        }
        assert(result == 0); // expected to fail and generate a counterexample that incorporates all calldata symbols
    }

    /// @custom:halmos --array-lengths p=1
    function check_StructArray(Point[] memory p, Point[2] memory q) public pure returns (uint result) {
        for (uint i = 0; i < p.length; i++) {
            unchecked {
                result += p[i].x + p[i].y;
            }
        }
        for (uint i = 0; i < q.length; i++) {
            unchecked {
                result += q[i].x + q[i].y;
            }
        }
        assert(result == 0); // expected to fail and generate a counterexample that incorporates all calldata symbols
    }

    /// @custom:halmos --array-lengths p=1,p[0]=1
    function check_StructArrayArray(
        Point[][] memory p,
        Point[2][] memory q,
        Point[][2] memory r,
        Point[2][2] memory s
    ) public pure returns (uint result) {
        for (uint i = 0; i < p.length; i++) {
            for (uint j = 0; j < p[i].length; j++) {
                unchecked {
                    result += p[i][j].x + p[i][j].y;
                }
            }
        }
        for (uint i = 0; i < q.length; i++) {
            for (uint j = 0; j < q[i].length; j++) {
                unchecked {
                    result += q[i][j].x + q[i][j].y;
                }
            }
        }
        for (uint i = 0; i < r.length; i++) {
            for (uint j = 0; j < r[i].length; j++) {
                unchecked {
                    result += r[i][j].x + r[i][j].y;
                }
            }
        }
        for (uint i = 0; i < s.length; i++) {
            for (uint j = 0; j < s[i].length; j++) {
                unchecked {
                    result += s[i][j].x + s[i][j].y;
                }
            }
        }
        assert(result == 0); // expected to fail and generate a counterexample that incorporates all calldata symbols
    }
}

/// @custom:halmos --solver-timeout-assertion 0
contract StructTest2 {
    struct P {
        uint x;
        uint[] y;
        uint z;
    }

    struct S {
        uint f1;
        P f2;
        uint[] f3;
        P[] f4;
        uint[1] f5;
        P[][] f6;
    }

    /// @custom:halmos --array-lengths s=1
    function check_S(P memory p, S[] memory s) public pure returns (uint result) {
        unchecked {
            result += sum_P(p);
            for (uint i = 0; i < s.length; i++) {
                result += sum_S(s[i]);
            }
        }
        assert(result == 0); // expected to fail and generate a counterexample that incorporates all calldata symbols
    }

    function sum_P(P memory p) internal pure returns (uint result) {
        unchecked {
            result += p.x;
            for (uint i = 0; i < p.y.length; i++) {
                result += p.y[i];
            }
            result += p.z;
        }
    }

    function sum_S(S memory s) internal pure returns (uint result) {
        unchecked {
            result += s.f1;
            result += sum_P(s.f2);
            for (uint i = 0; i < s.f3.length; i++) {
                result += s.f3[i];
            }
            for (uint i = 0; i < s.f4.length; i++) {
                result += sum_P(s.f4[i]);
            }
            result += s.f5[0];
            for (uint i = 0; i < s.f6.length; i++) {
                for (uint j = 0; j < s.f6[i].length; j++) {
                    result += sum_P(s.f6[i][j]);
                }
            }
        }
    }
}
