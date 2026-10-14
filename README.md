# Base Guardrail Agent 🛡️
> Autonomous Security & Token Risk Firewall for AI Agents on Base L2.

[![Network](https://img.shields.io/badge/Network-Base_L2-blue.svg)](https://base.org)
[![Protocol](https://img.shields.io/badge/PayProtocol-x402_Standard-green.svg)](https://x402.org)
[![Standard](https://img.shields.io/badge/AI_Standard-MCP_v1.0-orange.svg)](https://modelcontextprotocol.io)

An autonomous pre-transaction security firewall and risk analysis node designed for Onchain AI Agents, LangChain Bots, and AgentKit tools executing transactions on the Base Layer-2 network.

---

## 🚀 Service Information

- **Service Base URL**: `https://base-risk-agent.onrender.com`
- **MCP Manifest Specification**: `https://base-risk-agent.onrender.com/.well-known/mcp.json`
- **Agent Discovery Endpoint**: `https://base-risk-agent.onrender.com/agent.json`
- **Payment Protocol**: `x402 Protocol` ($0.01 USDC / Request)
- **Settlement Network**: Base Mainnet (CAIP-2: `eip155:8453`)
- **Recipient Wallet**: `0x141f20cb17221ea7a30cfb676ff2860afaf2ee9c`

---

## ⚙️ Protocols & Standards Compatibility

- **Model Context Protocol (MCP)**: Native tool schema discovery at `/.well-known/mcp.json` for seamless integration into Claude, LangChain, and Cursor Agent harnesses.
- **x402 Micropayments**: HTTP 402 `PAYMENT-REQUIRED` standard compliance with `PAYMENT-SIGNATURE` headers for gasless $0.01 USDC pre-authorizations.
- **Coinbase AgentKit**: Plug-and-Play Custom Action Provider support for autonomous trading workflows.

---

## 📡 API Endpoints

### 1. Agent & MCP Metadata (Public)
* **`GET /agent.json`** or **`GET /.well-known/mcp.json`**
* **Access**: Free / Open Specification
* **Description**: Returns tool capabilities, parameter schemas, and x402 payment requirements for LLM context injection.

### 2. Autonomous Risk & Security Inspection
* **`GET /v1/check-risk?address={EVM_ADDRESS}`**
* **Access**: Requires x402 Micropayment ($0.01 USDC)
* **Headers**: `PAYMENT-SIGNATURE: <x402_auth_payload>` or `Authorization: Bearer <tx_hash>`

#### Response Schema Example:
```json
{
  "status": "success",
  "data": {
    "target_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "risk_score": 0.05,
    "action_recommendation": "ALLOW",
    "threat_flags": [],
    "contract_verified": true,
    "timestamp": 1791936000
  }
}

Integration Guide for Autonomous AI Agents
Option 1: Integrating with Coinbase AgentKit
You can register this security inspector as a custom action in your CDP AgentKit workflow:

from cdp_agentkit_core.actions import create_action
import requests

@create_action(
    name="check_base_address_risk",
    description="Check token or address security risk on Base before executing swaps or contract interactions. Costs 0.01 USDC via x402.",
)
def check_base_address_risk(address: str, payment_signature: str) -> str:
    url = "[https://base-risk-agent.onrender.com/v1/check-risk](https://base-risk-agent.onrender.com/v1/check-risk)"
    headers = {"PAYMENT-SIGNATURE": payment_signature}
    
    response = requests.get(url, params={"address": address}, headers=headers)
    return response.text

Option 2: LangChain Tool Wrapper

import requests
from langchain_core.tools import tool

@tool
def base_security_firewall(address: str, payment_signature: str) -> dict:
    """
    Acts as an automated pre-execution firewall for Base transactions.
    Checks risk scores and malicious behavior flags via x402 ($0.01 USDC).
    """
    url = "[https://base-risk-agent.onrender.com/v1/check-risk](https://base-risk-agent.onrender.com/v1/check-risk)"
    headers = {"PAYMENT-SIGNATURE": payment_signature}
    
    response = requests.get(url, params={"address": address}, headers=headers)
    return response.json()

Quick Test (cURL)

curl -X GET "[https://base-risk-agent.onrender.com/v1/check-risk?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913](https://base-risk-agent.onrender.com/v1/check-risk?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)" \
     -H "PAYMENT-SIGNATURE: <YOUR_X402_PAYMENT_SIGNATURE>"

License
MIT License - Open for ecosystem adaptation and Grants retro-funding evaluations.
