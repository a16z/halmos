// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

/// @notice from https://github.com/kmbarry1/fund-eq-of-dai-certora/blob/master/Vat.sol

/// vat.sol -- Dai CDP database

// Note: this is a somewhat updated version from that on Ethereum mainnet,
// representing an intermediate product during preparation for deployment of
// MCD on other domains. See https://github.com/makerdao/xdomain-dss. It is not
// recommended to use or deploy this version. This repo is for pedagogical
// purposes only.

// Copyright (C) 2018 Rain <rainbreak@riseup.net>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

contract Vat {
    // --- Data ---
    mapping (address => uint256) public wards;

    mapping(address => mapping (address => uint256)) public can;

    struct Ilk {
        uint256 Art;   // Total Normalised Debt     [wad]
        uint256 rate;  // Accumulated Rates         [ray]
        uint256 spot;  // Price with Safety Margin  [ray]
        uint256 line;  // Debt Ceiling              [rad]
        uint256 dust;  // Urn Debt Floor            [rad]
    }
    struct Urn {
        uint256 ink;   // Locked Collateral  [wad]
        uint256 art;   // Normalised Debt    [wad]
    }

    mapping (bytes32 => Ilk)                       public ilks;
    mapping (bytes32 => mapping (address => Urn )) public urns;
    mapping (bytes32 => mapping (address => uint)) public gem;  // [wad]
    mapping (address => uint256)                   public dai;  // [rad]
    mapping (address => uint256)                   public sin;  // [rad]

    uint256 public debt;  // Total Dai Issued    [rad]
    uint256 public vice;  // Total Unbacked Dai  [rad]
    uint256 public Line;  // Total Debt Ceiling  [rad]
    uint256 public live;  // Active Flag

    // --- Events ---
    event Rely(address indexed usr);
    event Deny(address indexed usr);
    event Init(bytes32 indexed ilk);
    event File(bytes32 indexed what, uint256 data);
    event File(bytes32 indexed ilk, bytes32 indexed what, uint256 data);
    event Cage();
    event Hope(address indexed from, address indexed to);
    event Nope(address indexed from, address indexed to);
    event Slip(bytes32 indexed ilk, address indexed usr, int256 wad);
    event Flux(bytes32 indexed ilk, address indexed src, address indexed dst, uint256 wad);
    event Move(address indexed src, address indexed dst, uint256 rad);
    event Frob(bytes32 indexed i, address indexed u, address v, address w, int256 dink, int256 dart);
    event Fork(bytes32 indexed ilk, address indexed src, address indexed dst, int256 dink, int256 dart);
    event Grab(bytes32 indexed i, address indexed u, address v, address w, int256 dink, int256 dart);
    event Heal(address indexed u, uint256 rad);
    event Suck(address indexed u, address indexed v, uint256 rad);
    event Fold(bytes32 indexed i, address indexed u, int256 rate);

    modifier auth {
        require(wards[msg.sender] == 1, "Vat/not-authorized");
        _;
    }

    function wish(address bit, address usr) internal view returns (bool) {
        return either(bit == usr, can[bit][usr] == 1);
    }

    // --- Init ---
    constructor() {
        wards[msg.sender] = 1;
        live = 1;
        emit Rely(msg.sender);
    }

    // --- Math ---
    function _add(uint256 x, int256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x + uint256(y);
        }
        require(y >= 0 || z <= x);
        require(y <= 0 || z >= x);
    }

    function _sub(uint256 x, int256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x - uint256(y);
        }
        require(y <= 0 || z <= x);
        require(y >= 0 || z >= x);
    }

    function _int256(uint256 x) internal pure returns (int256 y) {
        require((y = int256(x)) >= 0);
    }

    // --- Administration ---
    function rely(address usr) external auth {
        require(live == 1, "Vat/not-live");
        wards[usr] = 1;
        emit Rely(usr);
    }

    function deny(address usr) external auth {
        require(live == 1, "Vat/not-live");
        wards[usr] = 0;
        emit Deny(usr);
    }

    function init(bytes32 ilk) external auth {
        require(ilks[ilk].rate == 0, "Vat/ilk-already-init");
        ilks[ilk].rate = 10 ** 27;
        emit Init(ilk);
    }

    function file(bytes32 what, uint256 data) external auth {
        require(live == 1, "Vat/not-live");
        if (what == "Line") Line = data;
        else revert("Vat/file-unrecognized-param");
        emit File(what, data);
    }

    function file(bytes32 ilk, bytes32 what, uint256 data) external auth {
        require(live == 1, "Vat/not-live");
        if (what == "spot") ilks[ilk].spot = data;
        else if (what == "line") ilks[ilk].line = data;
        else if (what == "dust") ilks[ilk].dust = data;
        else revert("Vat/file-unrecognized-param");
        emit File(ilk, what, data);
    }

    function cage() external auth {
        live = 0;
        emit Cage();
    }

    // --- Structs getters ---
    function Art(bytes32 ilk) external view returns (uint256 Art_) {
        Art_ = ilks[ilk].Art;
    }

    function rate(bytes32 ilk) external view returns (uint256 rate_) {
        rate_ = ilks[ilk].rate;
    }

    function spot(bytes32 ilk) external view returns (uint256 spot_) {
        spot_ = ilks[ilk].spot;
    }

    function line(bytes32 ilk) external view returns (uint256 line_) {
        line_ = ilks[ilk].line;
    }

    function dust(bytes32 ilk) external view returns (uint256 dust_) {
        dust_ = ilks[ilk].dust;
    }

    function ink(bytes32 ilk, address urn) external view returns (uint256 ink_) {
        ink_ = urns[ilk][urn].ink;
    }

    function art(bytes32 ilk, address urn) external view returns (uint256 art_) {
        art_ = urns[ilk][urn].art;
    }

    // --- Allowance ---
    function hope(address usr) external {
        can[msg.sender][usr] = 1;
        emit Hope(msg.sender, usr);
    }

    function nope(address usr) external {
        can[msg.sender][usr] = 0;
        emit Nope(msg.sender, usr);
    }

    // --- Fungibility ---
    function slip(bytes32 ilk, address usr, int256 wad) external auth {
        gem[ilk][usr] = _add(gem[ilk][usr], wad);
        emit Slip(ilk, usr, wad);
    }

    function flux(bytes32 ilk, address src, address dst, uint256 wad) external {
        require(wish(src, msg.sender), "Vat/not-allowed");
        gem[ilk][src] = gem[ilk][src] - wad;
        gem[ilk][dst] = gem[ilk][dst] + wad;
        emit Flux(ilk, src, dst, wad);
    }

    function move(address src, address dst, uint256 rad) external {
        require(wish(src, msg.sender), "Vat/not-allowed");
        dai[src] = dai[src] - rad;
        dai[dst] = dai[dst] + rad;
        emit Move(src, dst, rad);
    }

    function either(bool x, bool y) internal pure returns (bool z) {
        assembly{ z := or(x, y)}
    }

    function both(bool x, bool y) internal pure returns (bool z) {
        assembly{ z := and(x, y)}
    }

    // --- CDP Manipulation ---
    function frob(bytes32 i, address u, address v, address w, int256 dink, int256 dart) external {
        // system is live
        require(live == 1, "Vat/not-live");

        Urn memory urn = urns[i][u];
        Ilk memory ilk = ilks[i];
        // ilk has been initialised
        require(ilk.rate != 0, "Vat/ilk-not-init");

        urn.ink = _add(urn.ink, dink);
        urn.art = _add(urn.art, dart);
        ilk.Art = _add(ilk.Art, dart);

        int256 dtab = _int256(ilk.rate) * dart;
        uint256 tab = ilk.rate * urn.art;
        debt     = _add(debt, dtab);

        // either debt has decreased, or debt ceilings are not exceeded
        require(either(dart <= 0, both(ilk.Art * ilk.rate <= ilk.line, debt <= Line)), "Vat/ceiling-exceeded");
        // urn is either less risky than before, or it is safe
        require(either(both(dart <= 0, dink >= 0), tab <= urn.ink * ilk.spot), "Vat/not-safe");

        // urn is either more safe, or the owner consents
        require(either(both(dart <= 0, dink >= 0), wish(u, msg.sender)), "Vat/not-allowed-u");
        // collateral src consents
        require(either(dink <= 0, wish(v, msg.sender)), "Vat/not-allowed-v");
        // debt dst consents
        require(either(dart >= 0, wish(w, msg.sender)), "Vat/not-allowed-w");

        // urn has no debt, or a non-dusty amount
        require(either(urn.art == 0, tab >= ilk.dust), "Vat/dust");

        gem[i][v] = _sub(gem[i][v], dink);
        dai[w]    = _add(dai[w],    dtab);

        urns[i][u] = urn;
        ilks[i]    = ilk;

        emit Frob(i, u, v, w, dink, dart);
    }

    // --- CDP Fungibility ---
    function fork(bytes32 ilk, address src, address dst, int256 dink, int256 dart) external {
        Urn storage u = urns[ilk][src];
        Urn storage v = urns[ilk][dst];
        Ilk storage i = ilks[ilk];

        u.ink = _sub(u.ink, dink);
        u.art = _sub(u.art, dart);
        v.ink = _add(v.ink, dink);
        v.art = _add(v.art, dart);

        uint256 utab = u.art * i.rate;
        uint256 vtab = v.art * i.rate;

        // both sides consent
        require(both(wish(src, msg.sender), wish(dst, msg.sender)), "Vat/not-allowed");

        // both sides safe
        require(utab <= u.ink * i.spot, "Vat/not-safe-src");
        require(vtab <= v.ink * i.spot, "Vat/not-safe-dst");

        // both sides non-dusty
        require(either(utab >= i.dust, u.art == 0), "Vat/dust-src");
        require(either(vtab >= i.dust, v.art == 0), "Vat/dust-dst");

        emit Fork(ilk, src, dst, dink, dart);
    }

    // --- CDP Confiscation ---
    function grab(bytes32 i, address u, address v, address w, int256 dink, int256 dart) external auth {
        Urn storage urn = urns[i][u];
        Ilk storage ilk = ilks[i];

        urn.ink = _add(urn.ink, dink);
        urn.art = _add(urn.art, dart);
        ilk.Art = _add(ilk.Art, dart);

        int256 dtab = _int256(ilk.rate) * dart;

        gem[i][v] = _sub(gem[i][v], dink);
        sin[w]    = _sub(sin[w],    dtab);
        vice      = _sub(vice,      dtab);

        emit Grab(i, u, v, w, dink, dart);
    }

    // --- Settlement ---
    function heal(uint256 rad) external {
        address u = msg.sender;
        sin[u] = sin[u] - rad;
        dai[u] = dai[u] - rad;
        vice   = vice   - rad;
        debt   = debt   - rad;

        emit Heal(msg.sender, rad);
    }

    function suck(address u, address v, uint256 rad) external auth {
        sin[u] = sin[u] + rad;
        dai[v] = dai[v] + rad;
        vice   = vice   + rad;
        debt   = debt   + rad;

        emit Suck(u, v, rad);
    }

    // --- Rates ---
    function fold(bytes32 i, address u, int256 rate_) external auth {
        require(live == 1, "Vat/not-live");
        Ilk storage ilk = ilks[i];
        ilk.rate    = _add(ilk.rate, rate_);
        int256 rad  = _int256(ilk.Art) * rate_;
        dai[u]      = _add(dai[u], rad);
        debt        = _add(debt,   rad);

        emit Fold(i, u, rate_);
    }
}
