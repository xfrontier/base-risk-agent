# base-risk-agent
Base chain security &amp; risk check Agent API (x402 enabled）
# Base Risk Checker Agent (x402 Enabled)

An automated, pay-per-use token security risk analysis Agent deployed on the Base L2 network.

## 🚀 Service Information
- **Service Base URL**: `https://base-risk-agent.onrender.com`
- **Agent Manifest**: `https://base-risk-agent.onrender.com/agent.json`
- **Payment Protocol**: x402 Protocol ($0.01 USDC / Request)
- **Network**: Base (Layer 2)
- **Pay To Wallet**: `0x141f20cb17221ea7a30cfb676ff2860afaf2ee9c`

## 📡 API Endpoints

### 1. Agent Metadata
- **GET** `/agent.json`
- **Access**: Free / Public

### 2. Token Risk Inspection
- **GET** `/v1/check-risk?target_address={TOKEN_CONTRACT_ADDRESS}`
- **Access**: Requires x402 Payment ($0.01 USDC)
- **Header**: `Authorization: Bearer <tx_hash>` or `X-402-Payment: <tx_hash>`

## 💡 Quick Start (Example Request)

```python
import requests

url = "[https://base-risk-agent.onrender.com/v1/check-risk](https://base-risk-agent.onrender.com/v1/check-risk)"
params = {"target_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}
headers = {"Authorization": "Bearer tx_hash_here"}

response = requests.get(url, params=params, headers=headers)
print(response.json())
