import os
import requests
from fastapi import FastAPI, Request
from x402 import x402ResourceServerSync

app = FastAPI(title="Base Risk Checker Agent")

# ⚠️ 替换为你的 Coinbase 钱包地址 (0x 开头)
RECEIVER_WALLET = "0x141f20cb17221ea7a30cfb676ff2860afaf2ee9c"

# 初始化 x402 收款配置：在 Base 链上为每次请求收取 0.01 USDC
x402_server = x402ResourceServerSync(
    pay_to_address=RECEIVER_WALLET,
    price_usdc=0.01,
    network="base"
)

@app.middleware("http")
async def x402_protection_middleware(request: Request, call_next):
    """拦截器：未付费返回 HTTP 402，已付费放行"""
    if request.url.path in ["/docs", "/openapi.json", "/"]:
        return await call_next(request)
        
    is_paid, response_or_header = x402_server.verify_request(request)
    if not is_paid:
        return response_or_header

    return await call_next(request)

@app.get("/v1/check-risk")
def check_token_risk(target_address: str):
    """检测目标 Token/合约的链上风险"""
    try:
        url = f"https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses={target_address}"
        res = requests.get(url, timeout=5).json()
        data = res.get("result", {}).get(target_address.lower(), {})

        if not data:
            return {"status": "unknown", "message": "未查询到该合约的链上数据"}

        is_honeypot = data.get("is_honeypot", "0") == "1"
        is_open_source = data.get("is_open_source", "0") == "1"
        sell_tax = float(data.get("sell_tax", "0"))

        risk_score = 0
        risk_factors = []

        if is_honeypot:
            risk_score += 100
            risk_factors.append("HONEYPOT_DETECTED (貔貅盘陷阱)")
        if not is_open_source:
            risk_score += 40
            risk_factors.append("CONTRACT_NOT_OPEN_SOURCE (代码未开源)")
        if sell_tax > 0.1:
            risk_score += 30
            risk_factors.append(f"HIGH_SELL_TAX (高卖出税 {sell_tax*100}%)")

        return {
            "status": "success",
            "target_address": target_address,
            "is_safe": risk_score < 50,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "recommendation": "REJECT" if risk_score >= 50 else "PASS"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
