// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// Differential probe: same bytecode, DIFFERENT result on EVM vs TVM.
//  - p3(x): precompile 0x03 is RIPEMD160 on EVM, but TIP-272 "TwiceHash"
//    (sha256(sha256(...))) on TVM — an EVM-ported contract expecting RIPEMD160
//    silently gets a wrong hash, no revert.
//  - difficulty()/gaslimit(): block.difficulty & block.gaslimit are per-block on
//    EVM but CONSTANTS (0) on TVM.
contract TvmDiff {
    function p3(bytes calldata x) external view returns (bytes32 out) {
        (bool ok, bytes memory r) = address(0x03).staticcall(x);
        require(ok, "precompile 0x03 call failed");
        assembly { out := mload(add(r, 32)) }   // first 32 bytes of the return
    }
    function difficulty() external view returns (uint256) { return block.difficulty; }
    function gaslimit()   external view returns (uint256) { return block.gaslimit; }
}
