import os
import requests
from fastapi import FastAPI, Request, Response, status

# 1. 先初始化 FastAPI 应用（这一行必须放在最前面！）
app = FastAPI(title="Base Risk Checker Agent")

# ⚠️ 替换为你的 Coinbase 钱包地址 (0x 开头)
RECEIVER_WALLET = "0x141f20cb17221ea7a30cfb676ff2860afaf2ee9c"

# 2. agent.json 元数据公开接口
@app.get("/agent.json")
def get_agent_metadata():
    return {
        "name": "Base Risk Checker Agent",
        "description": "Automated token risk analysis agent on Base L2 providing honeypot and sell-tax detection.",
        "version": "1.0.0",
        "payment": {
            "protocol": "x402",
            "price_usdc": "0.01",
            "network": "base",
            "pay_to": RECEIVER_WALLET
        },
        "endpoints": [
            {
                "path": "/v1/check-risk",
                "method": "GET",
                "description": "Check safety and honeypot risk for a specific token contract address."
            }
        ]
    }

# 3. x402 门禁拦截器
@app.middleware("http")
async def x402_protection_middleware(request: Request, call_next):
    """x402 协议标准拦截器"""
    # 白名单：公开访问文档、首页和 agent.json
    if request.url.path in ["/docs", "/openapi.json", "/", "/agent.json"]:
        return await call_next(request)
        
    # 检查请求头中是否包含凭证
    x402_payment = request.headers.get("X-402-Payment") or request.headers.get("Authorization")
    
    # 未付款或没有凭证，返回标准的 402 Payment Required
    if not x402_payment:
        return Response(
            content='{"error": "Payment Required", "price_usdc": "0.01", "network": "base", "pay_to": "' + RECEIVER_WALLET + '"}',
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            media_type="application/json",
            headers={
                "X-402-Price": "0.01",
                "X-402-Network": "base",
                "X-402-Pay-To": RECEIVER_WALLET
            }
        )

    return await call_next(request)

# 4. 风控查询业务接口
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

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
