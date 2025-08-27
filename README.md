version: "3.8"
services:
  aggregator:
    build: ./aggregator
    container_name: aggregator
    env_file:
      - ./config.env
    restart: unless-stopped
    volumes:
      - ./data:/app/data
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"
        FROM python:3.11-slim

WORKDIR /app

# system deps for cryptography and bitcoin/solana libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libsecp256k1-dev curl git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aggregator.py .
COPY utils.py . || true

# create data dir
RUN mkdir -p /app/data
VOLUME /app/data

CMD ["python", "aggregator.py"]
web3==6.3.0
requests
python-bitcoinlib==0.12.1
solana==0.25.0
cryptography
pyyaml
#!/usr/bin/env python3
"""
Aggregator: polls balances for ETH, BTC, SOL, DOGE addresses and sweeps to central addresses
Config via environment variables (see config.example.env)
RUN IN DRY_RUN=true until tested.
"""

import os
import time
import json
import logging
from datetime import datetime, timedelta

# Ethereum
from web3 import Web3, HTTPProvider

# Bitcoin
from bitcoin import SelectParams
from bitcoin.rpc import Proxy as BitcoinProxy

# Solana
from solana.rpc.api import Client as SolClient
from solana.transaction import Transaction
from solana.keypair import Keypair
from solana.rpc.types import TxOpts
from solana.publickey import PublicKey

# Generic
import requests
import base64

# ---- Logging ----
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")

DRY_RUN = os.getenv("DRY_RUN", "true").lower() in ("1", "true", "yes")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))  # seconds

# Sweep thresholds and inactivity window
ETH_THRESHOLD_WEI = int(os.getenv("ETH_THRESHOLD_WEI", str(10000000000000000)))  # 0.01 ETH default
BTC_THRESHOLD_SAT = int(os.getenv("BTC_THRESHOLD_SAT", str(100000)))  # 0.001 BTC default
SOL_THRESHOLD_LAMPORT = int(os.getenv("SOL_THRESHOLD_LAMPORT", str(10000000)))  # 0.01 SOL default (1 SOL = 1e9 lamports)
DOGE_THRESHOLD = float(os.getenv("DOGE_THRESHOLD", "10.0"))  # 10 DOGE default

INACTIVITY_DAYS = int(os.getenv("INACTIVITY_DAYS", "30"))

# Destination addresses (where aggregated funds flow)
ETH_DEST = os.getenv("ETH_DEST")  # e.g., your main ETH collector
BTC_DEST = os.getenv("BTC_DEST")
SOL_DEST = os.getenv("SOL_DEST")
DOGE_DEST = os.getenv("DOGE_DEST")

# Source addresses (your earning addresses)
ETH_SRC = os.getenv("ETH_SRC")
BTC_SRC = os.getenv("BTC_SRC")
SOL_SRC = os.getenv("SOL_SRC")
DOGE_SRC = os.getenv("DOGE_SRC")

# RPC / credentials
ETH_RPC = os.getenv("ETH_RPC", "http://localhost:8545")
BTC_RPC_USER = os.getenv("BTC_RPC_USER")
BTC_RPC_PASS = os.getenv("BTC_RPC_PASS")
BTC_RPC_URL = os.getenv("BTC_RPC_URL", "http://127.0.0.1:8332")
SOL_RPC = os.getenv("SOL_RPC", "https://api.mainnet-beta.solana.com")
DOGE_RPC_USER = os.getenv("DOGE_RPC_USER")
DOGE_RPC_PASS = os.getenv("DOGE_RPC_PASS")
DOGE_RPC_URL = os.getenv("DOGE_RPC_URL", "http://127.0.0.1:22555")

# Private keys for signing (ENV only) - highly sensitive
ETH_PRIV = os.getenv("ETH_PRIV")  # 0x...
BTC_WIF = os.getenv("BTC_WIF")    # WIF for BTC_SRC
SOL_PRIV_BASE64 = os.getenv("SOL_PRIV_BASE64")  # base64-encoded private key bytes for solana Keypair
DOGE_WIF = os.getenv("DOGE_WIF")

# last activity tracking file
LAST_ACTIVITY_FILE = "/app/data/last_activity.json"
os.makedirs("/app/data", exist_ok=True)

def load_last_activity():
    if os.path.exists(LAST_ACTIVITY_FILE):
        with open(LAST_ACTIVITY_FILE, "r") as f:
            return json.load(f)
    return {}

def save_last_activity(d):
    with open(LAST_ACTIVITY_FILE, "w") as f:
        json.dump(d, f)

last_activity = load_last_activity()

# ----------------- Helpers -----------------
def eth_balance(w3, addr):
    return w3.eth.get_balance(addr)

def eth_nonce(w3, addr):
    return w3.eth.get_transaction_count(addr, "pending")

def sweep_eth(w3, src, priv, dest):
    bal = w3.eth.get_balance(src)
    if bal <= 0:
        logging.info("ETH: zero balance")
        return
    gas_price = w3.eth.gas_price
    gas_limit = 21000
    gas_cost = gas_price * gas_limit
    send_amount = bal - gas_cost
    if send_amount <= 0:
        logging.warning("ETH: Not enough to cover gas")
        return
    tx = {
        "to": dest,
        "value": send_amount,
        "gas": gas_limit,
        "gasPrice": gas_price,
        "nonce": w3.eth.get_transaction_count(src, "pending"),
        "chainId": w3.eth.chain_id
    }
    signed = w3.eth.account.sign_transaction(tx, private_key=priv)
    if DRY_RUN:
        logging.info(f"DRY_RUN ETH sweep prepared: from={src} to={dest} value={send_amount} gas={gas_cost}")
        return
    txh = w3.eth.send_raw_transaction(signed.rawTransaction)
    logging.info(f"ETH sweep broadcast txh={txh.hex()}")
    return txh.hex()

def get_btc_proxy():
    # URL form: http://user:pass@host:port
    from urllib.parse import urlparse
    # prefer explicit credentials
    if BTC_RPC_USER and BTC_RPC_PASS:
        parsed = BTC_RPC_URL
        return BitcoinProxy(service_url=BTC_RPC_URL, btc_conf_file=None, timeout=30, rpcuser=BTC_RPC_USER, rpcpassword=BTC_RPC_PASS)
    else:
        return BitcoinProxy(service_url=BTC_RPC_URL)

def btc_balance(proxy, addr):
    # Requires Bitcoin Core with addressindex or wallet use. We'll assume wallet control:
    try:
        sat = int(proxy.getreceivedbyaddress(addr) * 1e8)
        return sat
    except Exception as e:
        logging.warning("BTC balance check failed (RPC/wallet config may differ): %s", e)
        return 0

def sweep_btc(proxy, src_addr, wif, dest_addr):
    # This is a naive approach and requires wallet RPC or raw construction. Recommend using Bitcoin Core wallet sendtoaddress.
    if DRY_RUN:
        logging.info(f"DRY_RUN BTC sweep prepared: from={src_addr} to={dest_addr}")
        return
    try:
        # if src is in node wallet:
        txid = proxy.sendtoaddress(dest_addr, btc_sat_to_btc(btc_balance(proxy, src_addr)))
        logging.info(f"BTC sweep broadcast txid={txid}")
        return str(txid)
    except Exception as e:
        logging.error("BTC sweep failed: %s", e)

def btc_sat_to_btc(sat):
    return sat / 1e8

def sol_balance(client, pubkey_str):
    pub = PublicKey(pubkey_str)
    res = client.get_balance(pub)
    return res["result"]["value"]

def sweep_sol(client, src_pub, src_keypair, dest_pub):
    lamports = sol_balance(client, src_pub)
    if lamports <= 0:
        logging.info("SOL: zero lamports")
        return
    # estimate fee by simulation or set a safe leftover
    fee_payer = src_keypair
    # leave a small amount for fee: 5000 lamports
    amount = lamports - 5000
    if amount <= 0:
        logging.warning("SOL: not enough to cover fee")
        return
    txn = Transaction()
    txn.add(
        # instruction: simple transfer
        solana.system_program.transfer(
            solana.system_program.TransferParams(
                from_pubkey=PublicKey(src_pub),
                to_pubkey=PublicKey(dest_pub),
                lamports=amount
            )
        )
    )
    if DRY_RUN:
        logging.info(f"DRY_RUN SOL sweep prepared: from={src_pub} to={dest_pub} lamports={amount}")
        return
    resp = client.send_transaction(txn, src_keypair, opts=TxOpts(skip_preflight=False, preflight_commitment="confirmed"))
    logging.info(f"SOL sweep sent: {resp}")

def doge_balance(proxy, addr):
    # Dogecoin node wallet required; using RPC getreceivedbyaddress as simple approach
    try:
        sat = proxy.getreceivedbyaddress(addr)
        return float(sat)
    except Exception as e:
        logging.warning("DOGE balance check failed: %s", e)
        return 0.0

def sweep_doge(proxy, src_addr, wif, dest_addr):
    if DRY_RUN:
        logging.info(f"DRY_RUN DOGE sweep prepared: from={src_addr} to={dest_addr}")
        return
    try:
        txid = proxy.sendtoaddress(dest_addr, doge_balance(proxy, src_addr))
        logging.info(f"DOGE sweep broadcast txid={txid}")
        return str(txid)
    except Exception as e:
        logging.error("DOGE sweep failed: %s", e)

# ----------------- Main loop -----------------
def main_loop():
    # Setup clients
    w3 = Web3(HTTPProvider(ETH_RPC))
    logging.info("Connected to ETH RPC: %s, chainId=%s", ETH_RPC, getattr(w3.eth, "chain_id", "unknown"))

    btc_proxy = None
    try:
        btc_proxy = get_btc_proxy()
        logging.info("BTC RPC available")
    except Exception as e:
        logging.warning("BTC RPC not available: %s", e)

    sol_client = SolClient(SOL_RPC)
    logging.info("Solana RPC: %s", SOL_RPC)

    doge_proxy = None
    try:
        # reuse BitcoinProxy to talk to Dogecoin Core if RPC compatible
        if DOGE_RPC_USER and DOGE_RPC_PASS:
            doge_proxy = BitcoinProxy(service_url=DOGE_RPC_URL, rpcuser=DOGE_RPC_USER, rpcpassword=DOGE_RPC_PASS)
            logging.info("DOGE RPC available")
    except Exception as e:
        logging.warning("DOGE RPC not available: %s", e)

    # derive sol keypair if provided
    sol_keypair = None
    if SOL_PRIV_BASE64:
        key_bytes = base64.b64decode(SOL_PRIV_BASE64)
        sol_keypair = Keypair.from_secret_key(key_bytes)

    while True:
        try:
            now = datetime.utcnow()
            # ETH
            try:
                if ETH_SRC and ETH_DEST:
                    bal = eth_balance(w3, ETH_SRC)
                    logging.info("ETH balance for %s = %s wei", ETH_SRC, bal)
                    last = last_activity.get("eth", {}).get("last_tx_ts")
                    last_ts = datetime.fromisoformat(last) if last else None
                    inactivity = (now - last_ts).days if last_ts else None
                    if bal >= ETH_THRESHOLD_WEI or (inactivity is not None and inactivity >= INACTIVITY_DAYS):
                        sweep_eth(w3, ETH_SRC, ETH_PRIV, ETH_DEST)
                        last_activity.setdefault("eth", {})["last_tx_ts"] = now.isoformat()
            except Exception as e:
                logging.exception("ETH handling error: %s", e)

            # BTC
            try:
                if BTC_SRC and BTC_DEST and btc_proxy:
                    b_sat = btc_balance(btc_proxy, BTC_SRC)
                    logging.info("BTC balance sat for %s = %s", BTC_SRC, b_sat)
                    last = last_activity.get("btc", {}).get("last_tx_ts")
                    last_ts = datetime.fromisoformat(last) if last else None
                    inactivity = (now - last_ts).days if last_ts else None
                    if b_sat >= BTC_THRESHOLD_SAT or (inactivity is not None and inactivity >= INACTIVITY_DAYS):
                        sweep_btc(btc_proxy, BTC_SRC, BTC_WIF, BTC_DEST)
                        last_activity.setdefault("btc", {})["last_tx_ts"] = now.isoformat()
            except Exception as e:
                logging.exception("BTC handling error: %s", e)

            # SOL
            try:
                if SOL_SRC and SOL_DEST:
                    s_bal = sol_balance(sol_client, SOL_SRC)
                    logging.info("SOL lamports for %s = %s", SOL_SRC, s_bal)
                    last = last_activity.get("sol", {}).get("last_tx_ts")
                    last_ts = datetime.fromisoformat(last) if last else None
                    inactivity = (now - last_ts).days if last_ts else None
                    if s_bal >= SOL_THRESHOLD_LAMPORT or (inactivity is not None and inactivity >= INACTIVITY_DAYS):
                        if sol_keypair is None:
                            logging.error("SOL sweep skipped: no SOL_PRIV_BASE64 provided for signing")
                        else:
                            sweep_sol(sol_client, SOL_SRC, sol_keypair, SOL_DEST)
                            last_activity.setdefault("sol", {})["last_tx_ts"] = now.isoformat()
            except Exception as e:
                logging.exception("SOL handling error: %s", e)

            # DOGE
            try:
                if DOGE_SRC and DOGE_DEST and doge_proxy:
                    d_bal = doge_balance(doge_proxy, DOGE_SRC)
                    logging.info("DOGE balance for %s = %s", DOGE_SRC, d_bal)
                    last = last_activity.get("doge", {}).get("last_tx_ts")
                    last_ts = datetime.fromisoformat(last) if last else None
                    inactivity = (now - last_ts).days if last_ts else None
                    if d_bal >= DOGE_THRESHOLD or (inactivity is not None and inactivity >= INACTIVITY_DAYS):
                        sweep_doge(doge_proxy, DOGE_SRC, DOGE_WIF, DOGE_DEST)
                        last_activity.setdefault("doge", {})["last_tx_ts"] = now.isoformat()
            except Exception as e:
                logging.exception("DOGE handling error: %s", e)

            # persist last activity
            save_last_activity(last_activity)

        except Exception as e:
            logging.exception("Main loop error: %s", e)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    logging.info("Aggregator starting (DRY_RUN=%s) Poll interval=%s", DRY_RUN, POLL_INTERVAL)
    main_loop() # GENERAL
DRY_RUN=true
POLL_INTERVAL=300
LOG_LEVEL=INFO
INACTIVITY_DAYS=30

# DESTINATION collectors (where funds will be swept)
ETH_DEST=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_DEST=bc1q5hfgzqtmvxhntqtervzr4ed424us8caqvf4ta2
SOL_DEST=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_DEST=DEXg6azA92NjRrPQn3qcEayKbJUyJsgWNP

# SOURCE earning addresses (your validator / earning addresses)
ETH_SRC=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_SRC=<your_btc_source_address_here>
SOL_SRC=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_SRC=<your_doge_source_address_here>

# THRESHOLDS
ETH_THRESHOLD_WEI=10000000000000000
BTC_THRESHOLD_SAT=100000
SOL_THRESHOLD_LAMPORT=10000000
DOGE_THRESHOLD=10.0

# RPC / CREDENTIALS
ETH_RPC=https://your-eth-node-or-infura:8545
ETH_PRIV=0xYOUR_ETH_PRIVATE_KEY_FOR_SRC  # store securely!

BTC_RPC_URL=http://127.0.0.1:8332
BTC_RPC_USER=rpcuser
BTC_RPC_PASS=rpcpass
BTC_WIF=<btc_wif_for_src_if_needed>

SOL_RPC=https://api.mainnet-beta.solana.com
SOL_PRIV_BASE64=<base64-of-64-bytes-secret-key>  # or use hardware signing

DOGE_RPC_URL=http://127.0.0.1:22555
DOGE_RPC_USER=rpcuser
DOGE_RPC_PASS=rpcpass
DOGE_WIF=<doge_wif_for_src_if_needed>
project/
  docker-compose.yml
  config.env   <-- from config.example.env (fill with secrets)
  data/        <-- persisted by docker
  aggregator/
    Dockerfile
    requirements.txt
    aggregator.py
    # from project root
docker compose build
docker compose up -d
docker compose logs -f aggregator[Unit]
Description=Crypto Aggregator Service
After=network.target

[Service]
WorkingDirectory=/opt/aggregator
ExecStart=/usr/bin/python3 /opt/aggregator/aggregator.py
EnvironmentFile=/opt/aggregator/config.env
Restart=always
RestartSec=10
User=validator
Group=validator
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
sudo mkdir -p /opt/aggregator
# copy files to /opt/aggregator
sudo chown -R validator:validator /opt/aggregator
sudo systemctl daemon-reload
sudo systemctl enable --now aggregator.service
sudo journalctl -u aggregator.service -f
# ====== Aggregator config.env (PRE-FILLED) ======
# SECURITY: keep this file private (chmod 600 config.env)

# GENERAL
DRY_RUN=true
POLL_INTERVAL=300
LOG_LEVEL=INFO
INACTIVITY_DAYS=30

# DESTINATION collectors (where funds will be swept)
ETH_DEST=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_DEST=bc1q5hfgzqtmvxhntqtervzr4ed424us8caqvf4ta2
SOL_DEST=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_DEST=DEXg6azA92NjRrPQn3qcEayKbJUyJsgWNP

# SOURCE earning addresses (your validator / earning addresses)
# If source == dest and you want to sweep from other derived addresses, adjust accordingly.
ETH_SRC=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_SRC=bc1q5hfgzqtmvxhntqtervzr4ed424us8caqvf4ta2
SOL_SRC=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_SRC=DEXg6azA92NjRrPQn3qcEayKbJUyJsgWNP

# THRESHOLDS (adjust to taste)
ETH_THRESHOLD_WEI=10000000000000000     # 0.01 ETH
BTC_THRESHOLD_SAT=100000                # 0.001 BTC
SOL_THRESHOLD_LAMPORT=10000000          # 0.01 SOL (1 SOL = 1e9 lamports)
DOGE_THRESHOLD=10.0                     # 10 DOGE

# ===================== RPC / CREDENTIALS (FILL THESE) =====================
# Ethereum RPC (node or Infura/Alchemy). Must be HTTP URL.
ETH_RPC=https://your-eth-node-or-infura:8545
# ETH private key for ETH_SRC (0x-prefixed). Prefer hardware signer instead of raw key.
ETH_PRIV=0xYOUR_ETH_PRIVATE_KEY_FOR_SRC

# Bitcoin RPC (Bitcoin Core). If using external wallet or electrum, adapt code.
BTC_RPC_URL=http://127.0.0.1:8332
BTC_RPC_USER=rpcuser
BTC_RPC_PASS=rpcpass
# If using a WIF for manual raw tx build / external signer (optional)
BTC_WIF=<btc_wif_for_src_if_needed>

# Solana RPC
SOL_RPC=https://api.mainnet-beta.solana.com
# Base64-encoded 64-byte secret key for solana Keypair (if using signing in script).
# Example: base64.b64encode(Keypair().secret_key).decode()
SOL_PRIV_BASE64=<base64-of-64-bytes-secret-key>

# Dogecoin RPC (Dogecoin Core)
DOGE_RPC_URL=http://127.0.0.1:22555
DOGE_RPC_USER=rpcuser
DOGE_RPC_PASS=rpcpass
DOGE_WIF=<doge_wif_for_src_if_needed>

# Optional: override aggregator behavior
# e.g., set DRY_RUN=false to enable broadcasting (do NOT do this until tested)
# DRY_RUN=false


# ====== Aggregator config.env (PRE-FILLED) ======
# SECURITY: keep this file private (chmod 600 config.env)

# GENERAL
DRY_RUN=true
POLL_INTERVAL=300
LOG_LEVEL=INFO
INACTIVITY_DAYS=30

# DESTINATION collectors (where funds will be swept)
ETH_DEST=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_DEST=bc1q5hfgzqtmvxhntqtervzr4ed424us8caqvf4ta2
SOL_DEST=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_DEST=DEXg6azA92NjRrPQn3qcEayKbJUyJsgWNP

# SOURCE earning addresses (your validator / earning addresses)
# If source == dest and you want to sweep from other derived addresses, adjust accordingly.
ETH_SRC=0xfa3d11c7e0ede9808fd80a8f94bed6a124bbf707
BTC_SRC=bc1q5hfgzqtmvxhntqtervzr4ed424us8caqvf4ta2
SOL_SRC=AKKJ3jZprXxhr3SEpTP3o7evCFfxtCvw7w6byeQGRs7n
DOGE_SRC=DEXg6azA92NjRrPQn3qcEayKbJUyJsgWNP

# THRESHOLDS (adjust to taste)
ETH_THRESHOLD_WEI=10000000000000000     # 0.01 ETH
BTC_THRESHOLD_SAT=100000                # 0.001 BTC
SOL_THRESHOLD_LAMPORT=10000000          # 0.01 SOL (1 SOL = 1e9 lamports)
DOGE_THRESHOLD=10.0                     # 10 DOGE

# ===================== RPC / CREDENTIALS (FILL THESE) =====================
# Ethereum RPC (node or Infura/Alchemy). Must be HTTP URL.
ETH_RPC=https://your-eth-node-or-infura:8545
# ETH private key for ETH_SRC (0x-prefixed). Prefer hardware signer instead of raw key.
ETH_PRIV=0xYOUR_ETH_PRIVATE_KEY_FOR_SRC

# Bitcoin RPC (Bitcoin Core). If using external wallet or electrum, adapt code.
BTC_RPC_URL=http://127.0.0.1:8332
BTC_RPC_USER=rpcuser
BTC_RPC_PASS=rpcpass
# If using a WIF for manual raw tx build / external signer (optional)
BTC_WIF=<btc_wif_for_src_if_needed>

# Solana RPC
SOL_RPC=https://api.mainnet-beta.solana.com
# Base64-encoded 64-byte secret key for solana Keypair (if using signing in script).
# Example: base64.b64encode(Keypair().secret_key).decode()
SOL_PRIV_BASE64=<base64-of-64-bytes-secret-key>

# Dogecoin RPC (Dogecoin Core)
DOGE_RPC_URL=http://127.0.0.1:22555
DOGE_RPC_USER=rpcuser
DOGE_RPC_PASS=rpcpass
DOGE_WIF=<doge_wif_for_src_if_needed>

# Optional: override aggregator behavior
# e.g., set DRY_RUN=false to enable broadcasting (do NOT do this until tested)
# DRY_RUN=false 
# secure the file
chmod 600 config.env

# bring up the stack (docker example)
docker compose build
docker compose up -d

# watch logs (aggregator)
docker compose logs -f aggregator

