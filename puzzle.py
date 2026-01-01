import json
import hashlib
import asyncio
import httpx
import time
import base64
import os
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from aiohttp import web

# ================= HARDCODED CONFIG =================

# Updated with your new Puzzle-Master JSON URL
JSON_URL = "https://gist.githubusercontent.com/sgshivam2000-ai/619ffaac8c96be909f9457bf94a50f6b/raw/ff16e8bfee3a1f6879c7036fed7111b1b0a4f0f5/me.json"

# Updated with your Key and Project ID
FIREBASE_KEY = "AIzaSyCF-M9WFi6IsTIn7G3hzG_nIi3rWA3XD6o"
PROJECT_ID = "puzzle-master-51426"

# Updated with your new Refresh Token
REFRESH_TOKEN = "AMf-vBxaHxJYzoI-VvCrOKJw5chRnjIk0YobAiqGF3dad8Mon2c69VMn-kKe-1hI0OtfCzswSPZKwOXApnmuHOaAttzPKBpxHTeME8xiarjA-FXJGeS1a6OdwNgZg4Cgc28SZKq1P31Q36MlpMoTnMmUkUPjxH23qWLyZtdJWTkfRBIgHnxvwUAeWSD5qGoXyMO11ky5n6YQZwGgJFgoIdKxsTZspDabG1Yb5lUN65zFvHunI8YEPTGVKsE-6tkZ6EY9btfy4dCayZPymDMEC5mQpTGBKoeyGS9M5XUu71Vpc4V-aGA_SU_jWVBylxXnBP2IiEvSC-AqMP4gTgGVNXR0zP-vNZ_jM145B3hfmBrUV21wvIJLbImJgPTKu19gT_g_3wrJsmT3KaDbpGcC7M1GMTVLeZUSI-6NZ75RWxlqHwViKCPJpQVFSVEXYKhGGrLK-jKlILMC"

BASE_URL = "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation"
SPOT_ID = "2238092"
SALT = "j8n5HxYA0ZVF"

ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"

REQUEST_TIMEOUT = 30
PORT = 10090 # Unique port to avoid address conflicts

# ====================================================

_last_timestamp = 0
_stats = {"start_time": time.time(), "status": "running"}

def log(msg: str):
    timestamp = time.strftime('%H:%M:%S')
    print(f"[{timestamp}] [BOT] {msg}", flush=True)

async def health_check(request):
    uptime = int(time.time() - _stats["start_time"])
    return web.json_response({"status": "running", "uptime": f"{uptime // 3600}h {(uptime % 3600) // 60}m"})

async def start_http_server():
    app = web.Application()
    app.router.add_get("/", health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        site = web.TCPSite(runner, '0.0.0.0', PORT)
        await site.start()
        log(f"Server live on port {PORT}")
    except Exception:
        log(f"Port {PORT} busy, skipping server...")

async def create_client():
    return httpx.AsyncClient(http2=True, timeout=httpx.Timeout(REQUEST_TIMEOUT), verify=False)

async def load_config(client):
    log("Fetching Latest Configuration...")
    r = await client.get(JSON_URL)
    # Fix for invalid control characters
    clean_text = "".join(c for c in r.text if ord(c) >= 32)
    data = json.loads(clean_text)
    user_id = data["client_params"]["publisher_supplied_user_id"]
    return {"user_id": user_id, "payload": json.dumps(data, separators=(",", ":"))}

class TokenManager:
    def __init__(self): # Fixed method name
        self.token, self.uid, self.expiry = None, None, 0

    async def get(self, client):
        if not self.token or time.time() >= self.expiry:
            r = await client.post(f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_KEY}",
                data={"grant_type": "refresh_token", "refresh_token": REFRESH_TOKEN})
            j = r.json()
            self.token, self.uid = j["id_token"], j["user_id"]
            self.expiry = time.time() + int(j["expires_in"]) - 30
            log(f"Auth Refreshed: {self.token[:10]}...")
        return self.token, self.uid

def build_hash_payload(user_id, url):
    global _last_timestamp
    now = max(int(time.time()), _last_timestamp + 1)
    _last_timestamp = now
    ts = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{url}{ts}{SALT}"
    return json.dumps({"user_id": user_id, "timestamp": now, "hash_value": hashlib.sha512(raw.encode()).hexdigest()}, separators=(",", ":"))

def encrypt_offer(offer_id):
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    raw = json.dumps({"offerId": offer_id}, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return {"data": {"data": base64.b64encode(cipher.encrypt(pad(raw, 16))).decode()}}

async def get_super_offer(client, token, uid):
    try:
        r = await client.post(f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}:runQuery",
            headers={"Authorization": f"Bearer {token}"},
            json={"structuredQuery": {"from": [{"collectionId": "superOffers"}], "where": {"fieldFilter": {"field": {"fieldPath": "status"}, "op": "NOT_EQUAL", "value": {"stringValue": "COMPLETED"}}}, "limit": 1}})
        for item in r.json():
            if "document" in item:
                f = item["document"]["fields"]
                return {"offerId": f["offerId"]["stringValue"], "fees": int(f.get("fees", {}).get("integerValue", 0))}
    except Exception: pass
    return None

async def run_fairbid(client, cfg):
    try:
        r = await client.post(f"{BASE_URL}?spotId={SPOT_ID}", content=cfg["payload"])
        if '"completion":"' in r.text:
            comp = r.text.split('"completion":"')[1].split('"')[0]
            await client.post(comp, content=build_hash_payload(cfg["user_id"], comp))
    except: pass

async def bot_loop():
    client = await create_client()
    try:
        cfg = await load_config(client)
        tm = TokenManager()
        while True:
            try:
                token, uid = await tm.get(client)
                offer = await get_super_offer(client, token, uid)
                
                if not offer:
                    log("Idle: No offers found. Waiting 60s...")
                    await asyncio.sleep(60) # Prevent stop after rounds
                    continue

                log(f"Target Found: {offer['offerId']} | Need {offer['fees']} Boosts")
                for i in range(offer["fees"] + 1):
                    await run_fairbid(client, cfg)
                    if i % 5 == 0: log(f"Boost Progress: {i}/{offer['fees']}")
                    await asyncio.sleep(0.5) # Stable speed

                for action in ["superOffer_unlock", "superOffer_claim"]:
                    await client.post(f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/{action}",
                        headers={"Authorization": f"Bearer {token}"}, json=encrypt_offer(offer["offerId"]))
                
                log(f"Claim Success: {offer['offerId']}")
                await asyncio.sleep(10)
            except Exception as e:
                log(f"Error in loop: {e}")
                await asyncio.sleep(10)
    finally:
        await client.aclose()

async def main():
    await start_http_server()
    await bot_loop()

if __name__ == "__main__":
    asyncio.run(main())
