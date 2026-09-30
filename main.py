import os
import sqlite3
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request, Query, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from web3 import Web3

# ------------------------------------------------------------------------------
# 1. 配置与常量声明
# ------------------------------------------------------------------------------
RECEIVER_ADDRESS = "0x141f20cb17221ea7a30cfb676ff2860afaf2ee9c".lower()
BASE_USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".lower()
BASE_RPC_URL = "https://mainnet.base.org"

# ERC-20 Transfer(address,address,uint256) 事件签名 Hash
TRANSFER_EVENT_SIGNATURE = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# 连接到 Base 主网
w3 = Web3(Web3.HTTPProvider(BASE_RPC_URL))

DB_PATH = "risk_agent.db"

# ------------------------------------------------------------------------------
# 2. 数据库初始化与日志记录（持久化存储 + 防重放）
# ------------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            endpoint TEXT,
            client_ip TEXT,
            status_code INTEGER,
            payment_tx_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_request(endpoint: str, client_ip: str, status_code: int, tx_hash: Optional[str] = None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_logs (timestamp, endpoint, client_ip, status_code, payment_tx_hash) VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), endpoint, client_ip, status_code, tx_hash)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database log error: {e}")

# ------------------------------------------------------------------------------
# 3. 链上 RPC 支付核验逻辑
# ------------------------------------------------------------------------------
def verify_base_usdc_payment(tx_hash: str) -> tuple[bool, str]:
    """
    核验交易 Hash 是否为合格的 >= 0.01 USDC 转账
    """
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        return False, "Invalid transaction hash format."

    try:
        # 1. 检查防重放（该 TxHash 是否已被使用过）
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM api_logs WHERE payment_tx_hash = ?", (tx_hash,))
        if cursor.fetchone():
            conn.close()
            return False, "This transaction hash has already been used (Replay Attack Prevention)."
        conn.close()

        # 2. 从 Base 链上拉取交易回执
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt or receipt.get("status") != 1:
            return False, "Transaction failed or not found on Base mainnet."

        # 3. 遍历 Logs 匹配 USDC 转账
        for log in receipt.get("logs", []):
            if log.get("address", "").lower() == BASE_USDC_ADDRESS:
                topics = log.get("topics", [])
                if topics and topics[0].hex().lower() == TRANSFER_EVENT_SIGNATURE:
                    # 解析接收者地址 (topics[2])
                    to_address = "0x" + topics[2].hex()[-40:].lower()
                    # 解析转账金额 (data hex -> int)
                    amount = int(log.get("data", "0x0").hex(), 16)

                    # 校验接收方与金额 (0.01 USDC = 10,000 units, 因为 USDC 是 6 位精度)
                    if to_address == RECEIVER_ADDRESS and amount >= 10000:
                        return True, "Payment verified successfully."

        return False, "Transaction does not contain valid >= $0.01 USDC transfer to receiver."
    except Exception as e:
        return False, f"Verification error: {str(e)}"

# ------------------------------------------------------------------------------
# 4. FastAPI 应用主体与中间件
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Base Risk Assessment Agent",
    description="x402 Protocol Enabled Security Risk Checking Agent on Base",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
def x402_protection_middleware(request: Request, call_next):
    # 只对受保护的风控 API 进行付费拦截，免除 agent.json、docs 等公开元数据
    protected_paths = ["/v1/check-risk"]
    client_ip = request.client.host if request.client else "unknown"

    if request.url.path in protected_paths:
        x402_payment = request.headers.get("X-402-Payment") or request.headers.get("Authorization")

        if not x402_payment:
            log_request(request.url.path, client_ip, 402)
            return JSONResponse(
                status_code=402,
                content={
                    "error": "Payment Required",
                    "protocol": "x402",
                    "price": "$0.01 USDC",
                    "network": "Base Mainnet",
                    "pay_to": RECEIVER_ADDRESS,
                    "usdc_token_contract": BASE_USDC_ADDRESS,
                    "message": "Please send 0.01 USDC on Base to pay_to and pass the transaction hash in X-402-Payment or Authorization header."
                }
            )

        # 提取格式化的 TxHash
        tx_hash = x402_payment.replace("Bearer ", "").strip()

        # 进行链上真实校验
        is_valid, msg = verify_base_usdc_payment(tx_hash)
        if not is_valid:
            log_request(request.url.path, client_ip, 402, tx_hash)
            return JSONResponse(
                status_code=402,
                content={
                    "error": "Invalid Payment Proof",
                    "detail": msg,
                    "provided_tx_hash": tx_hash
                }
            )

        # 校验通过，记录并放行
        log_request(request.url.path, client_ip, 200, tx_hash)

    response = call_next(request)
    return response

# ------------------------------------------------------------------------------
# 5. 业务 API 路由
# ------------------------------------------------------------------------------
@app.get("/")
def read_root():
    return {
        "agent": "Base Risk Assessment Agent",
        "status": "online",
        "docs": "/docs",
        "agent_manifest": "/agent.json"
    }

@app.get("/agent.json")
def get_agent_manifest():
    return {
        "schema_version": "v1",
        "name": "Base Risk Assessment Agent",
        "description": "Provides real-time GoPlus token security checks on Base network with x402 micro-payments.",
        "url": "https://base-risk-agent.onrender.com",
        "payment": {
            "protocol": "x402",
            "price_usdc": "0.01",
            "network": "base",
            "pay_to": RECEIVER_ADDRESS
        },
        "endpoints": [
            {
                "path": "/v1/check-risk",
                "method": "GET",
                "params": ["target_address"]
            }
        ]
    }

@app.get("/stats")
def get_stats():
    """查看 API 累计调用统计与收益概览"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM api_logs WHERE endpoint = '/v1/check-risk'")
    total_calls = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM api_logs WHERE endpoint = '/v1/check-risk' AND status_code = 200")
    paid_calls = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM api_logs WHERE endpoint = '/v1/check-risk' AND status_code = 402")
    blocked_calls = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "status": "online",
        "metrics": {
            "total_check_requests": total_calls,
            "successful_paid_calls": paid_calls,
            "unpaid_blocked_calls": blocked_calls,
            "total_revenue_usdc": f"${paid_calls * 0.01:.2f}"
        }
    }

@app.get("/v1/check-risk")
async def check_risk(target_address: str = Query(..., description="Target token or wallet address on Base")):
    """
    实际调用 GoPlus API 进行风控查询
    """
    goplus_url = f"https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses={target_address}"
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(goplus_url, timeout=10.0)
            data = res.json()
            return {
                "status": "success",
                "target_address": target_address,
                "chain": "base",
                "risk_data": data.get("result", {})
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"GoPlus API Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=True)
