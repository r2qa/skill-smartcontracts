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

    // 1e18 scaling ON a native-value (msg.value) path, single expression — must fire.
    function priceNative() external payable returns (uint256) {
        // ruleid: tron-native-value-decimals
        return msg.value * 1e18;
    }

    // Weak randomness from TVM constants — must fire.
    function pickWinner() external view returns (uint256) {
        // ruleid: tron-weak-randomness-tvm-constants
        return uint256(block.difficulty) % players;
    }

    // Ethereum 0xff CREATE2 preimage — wrong on TVM (0x41) — must fire.
    function predict(bytes32 salt, bytes32 codeHash) external view returns (address) {
        // ruleid: tron-create2-eth-prefix
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash)))));
    }

    mapping(address => uint256) credit;
    trcToken realTokenId;
    uint256 players;
}

// Safe contract: plain ERC20-style + ordinary 18-decimal WAD math NOT on a native path.
// None of the rules should fire anywhere in here.
contract PlainErc20Like {
    mapping(address => uint256) public balanceOf;
    uint256 public constant WAD = 1e18; // ok: tron-native-value-decimals

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    // 18-decimal share math with no msg.value in scope — must NOT fire.
    function toShares(uint256 assets, uint256 rate) external pure returns (uint256) {
        // ok: tron-native-value-decimals
        return (assets * 1e18) / rate;
    }
}

// Coverage for the low-level / EVM-assumption rules (batch 2). Each construct must fire.
contract TronNativeOps {
    function sends(address payable to, uint256 v) external {
        // ruleid: tron-native-send-stipend
        to.send(v);
        // ruleid: tron-native-send-stipend
        payable(to).transfer(v);
    }
    function auth() external view returns (bool) {
        // ruleid: tron-tx-origin-auth
        return tx.origin == msg.sender;
    }
    function rec(bytes32 h, uint8 vv, bytes32 r, bytes32 s) external pure returns (address) {
        // ruleid: tron-ecrecover-usage
        return ecrecover(h, vv, r, s);
    }
    function kill() external {
        // ruleid: tron-selfdestruct-usage
        selfdestruct(payable(msg.sender));
    }
    function dc(address t, bytes calldata d) external {
        // ruleid: tron-delegatecall-usage
        t.delegatecall(d);
    }
    function cv(address t) external payable {
        // ruleid: tron-lowlevel-call-value
        t.call{value: msg.value}("");
    }
    function mk(bytes32 salt) external returns (address) {
        // ruleid: tron-create2-new-salt
        TronNativeOps x = new TronNativeOps{salt: salt}();
        return address(x);
    }
}

// Negative cases (batch 2) — safe variants that must NOT fire.
contract SafeVariants {
    address owner;
    mapping(address=>uint256) balanceOf;
    // msg.sender auth — NOT tx.origin — must NOT fire tron-tx-origin-auth
    function ok_auth() external view returns (bool) {
        // ok: tron-tx-origin-auth
        return msg.sender == owner;
    }
    // ordinary ERC20 transfer — not payable().transfer / .send — must NOT fire native-send-stipend
    function ok_erc20(address token, address to, uint256 v) external {
        // ok: tron-native-send-stipend
        IERC20(token).transfer(to, v);
    }
    // low-level call WITHOUT value — must NOT fire tron-lowlevel-call-value
    function ok_call(address t, bytes calldata d) external {
        // ok: tron-lowlevel-call-value
        (bool s,) = t.call(d); require(s);
    }
}
