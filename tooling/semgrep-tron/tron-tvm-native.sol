// Test fixture for tron-tvm-native.yml — run: semgrep --test tooling/semgrep-tron/
// Vulnerable/hotspot contract: every TRON-native construct below MUST be flagged.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract TronVulnerable {
    // trcToken param straight from calldata, no allowlist/range check.
    // ruleid: tron-trctoken-param
    function deposit(trcToken id, uint256 amount) external payable {
        // ruleid: tron-trc10-msgtoken-context
        uint256 got = msg.tokenvalue;
        // ruleid: tron-trc10-msgtoken-context
        trcToken incoming = msg.tokenid;
        credit[msg.sender] += got;
    }

    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        // ruleid: tron-transfertoken-call
        msg.sender.transferToken(amount, realTokenId);
    }

    function balanceOfFake(trcToken id) external view returns (uint256) {
        // ruleid: tron-tokenbalance-call
        return address(this).tokenBalance(id);
    }

    function priceNative() external pure returns (uint256) {
        // ruleid: tron-native-value-decimals
        return 1 ether;
    }

    function scale(uint256 x) external pure returns (uint256) {
        // ruleid: tron-native-value-decimals
        return x * 1e18;
    }

    mapping(address => uint256) credit;
    trcToken realTokenId;
}

// Safe contract: a plain ERC20-style contract with NO TRON-native constructs.
// None of the rules should fire anywhere in here.
contract PlainErc20Like {
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function value() external payable returns (uint256) {
        return msg.value;
    }
}
