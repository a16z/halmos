// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// File cheatcodes (halmos#213): vm.readFile, vm.readFileBinary, vm.parseBytes, vm.projectRoot.
/// Access follows fs_permissions in foundry.toml: test/data is readable, test/data/private is not.
contract FileTest is Test {
    address deployed;

    // initcode of a contract that returns 42 for any call (as compiled by huff, say)
    bytes constant INITCODE = hex"600a600c600039600a6000f3602a60005260206000f3";

    function setUp() public {
        // the scenario from halmos#213: deploy bytecode that is not compiled by solc
        bytes memory initcode = vm.parseBytes(vm.readFile("test/data/initcode.hex"));
        address addr;
        assembly {
            addr := create(0, add(initcode, 0x20), mload(initcode))
        }
        require(addr != address(0), "deployment failed");
        deployed = addr;
    }

    function check_deployedFromFile(uint256 x) public {
        (bool success, bytes memory ret) = deployed.call(abi.encode(x));
        assert(success);
        assert(abi.decode(ret, (uint256)) == 42);
    }

    function check_readFile() public view {
        // returned as is, trailing newline included
        string memory text = vm.readFile("test/data/hello.txt");
        assert(keccak256(bytes(text)) == keccak256("hello\nworld\n"));
    }

    function check_readFileBinary() public view {
        bytes memory data = vm.readFileBinary("test/data/binary.bin");
        assert(keccak256(data) == keccak256(hex"00ff80"));
    }

    function check_readFile_normalizedPath() public view {
        string memory text = vm.readFile("test/data/private/../hello.txt");
        assert(keccak256(bytes(text)) == keccak256("hello\nworld\n"));
    }

    function check_projectRoot() public view {
        string memory path = string.concat(vm.projectRoot(), "/test/data/hello.txt");
        assert(keccak256(bytes(vm.readFile(path))) == keccak256("hello\nworld\n"));
    }

    function check_parseBytes() public view {
        assert(keccak256(vm.parseBytes("0x600a6000F3")) == keccak256(hex"600a6000f3"));
        assert(keccak256(vm.parseBytes("600a6000f3")) == keccak256(hex"600a6000f3"));
        assert(vm.parseBytes("0x").length == 0);
        assert(keccak256(vm.parseBytes(vm.readFile("test/data/initcode.hex"))) == keccak256(INITCODE));
    }

    // the following must error, as they do under forge test

    function check_readFile_notPermitted() public view {
        vm.readFile("foundry.toml");
    }

    function check_readFile_nestedDenial() public view {
        vm.readFile("test/data/private/secret.txt");
    }

    function check_readFile_escape() public view {
        vm.readFile("test/data/../../foundry.toml");
    }

    function check_readFile_missing() public view {
        vm.readFile("test/data/missing.txt");
    }

    function check_readFile_invalidUtf8() public view {
        vm.readFile("test/data/binary.bin");
    }

    function check_parseBytes_whitespace() public view {
        vm.parseBytes("0x600a\n");
    }

    function check_parseBytes_oddLength() public view {
        vm.parseBytes("0x123");
    }

    function check_parseBytes_symbolic(string memory s) public view {
        vm.parseBytes(s);
    }
}
