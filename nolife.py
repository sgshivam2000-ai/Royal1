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

JSON_URL = "https://gist.githubusercontent.com/CodeWithAlone1/e6e1bef645569e936fa03d3b5a00c831/raw/ac42937eb3faf53246dde6217f91de551e4031fd/Burger.json"

FIREBASE_KEY = "AIzaSyA80VcSTBCCc2eK5urAdPuVFDWo1F9gAds"
PROJECT_ID = "cash-monkey-1df41"

REFRESH_TOKEN = (
    "AMf-vByZqMklYokde7XZ5A-dxxfD2PWvQRyR_fcf8yHXnd4IApn6rmPfS8AgwiY7XOzbCudTF5QLH45Kj7efP4HQG0XDv5DUmK09nfEJWp8rb2-feYVlj-3KB1u4lTw9mMYNBXOuZcgZUYugk1lexrYI5bWcrHtKsSreB-GF-Dix_o8TCNOkVagDL8vkFfgM8gfU2JsIPrR3ORrPrGo-_cM5jdEw8NV-F_uC_5UhdgRnjS2BIClXMSsl_8xNa4uYVARoM9Vv-ZTSSn0PghKOeZAaE0Z8oCNq1B9-0SsbNfRPyEJ43KkMPPl5xhMl-XPTQti4yJGbLv9cDES2FHv8zfeuov9eRkNc7PIBTEIfYfRhuEcC6ml_n0QOSRr2jPQK727FWWWAFQCTlI3pUw6PPnKcmCsiKVYIfJvGLJAyXFx-wun_Xkh2umg"
)

BASE_URL = "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation"
SPOT_ID = "2605040"
SALT = "j8n5HxYA0ZVF"

ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"

REQUEST_TIMEOUT = 30
PORT = int(os.getenv("PORT", 10000))

# ====================================================

_last_timestamp = 0
_processed_offers = set()
_stats = {
    "start_time": time.time(),
    "status": "running"
}

# ---------------- LOG ---------------- #

def log(msg: str):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

# ---------------- HTTP SERVER (Keep-Alive) ---------------- #

async def health_check(request):
    uptime = int(time.time() - _stats["start_time"])
    hours = uptime // 3600
    minutes = (uptime % 3600) // 60
    
    return web.json_response({
        "status": "running",
        "uptime": f"{hours}h {minutes}m"
    })

async def start_http_server():
    app = web.Application()
    app.router.add_get("/", health_check)
    app.router.add_get("/health", health_check)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    log(f"[HTTP] Health check server running on port {PORT}")

# ---------------- CLIENT ---------------- #

async def create_client():
    return httpx.AsyncClient(
        http2=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Android)",
            "Accept": "application/json",
        },
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        verify=False,
    )

# ---------------- LOAD CONFIG FROM URL ---------------- #

async def load_config(client):
    log("[CONFIG] Fetching JSON data from URL...")
    try:
        r = await client.get(JSON_URL)
        r.raise_for_status()
        data = r.json()
        
        user_id = data["client_params"]["publisher_supplied_user_id"]
        log(f"[CONFIG] Loaded config for user: {user_id}")
        
        return {
            "user_id": user_id,
            "payload": json.dumps(data, separators=(",", ":")),
        }
    except Exception as e:
        log(f"[CONFIG] Failed to load config: {e}")
        raise

# ---------------- AUTH ---------------- #

async def get_id_token(client):
    r = await client.post(
        f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_KEY}",
        data={
            "grant_type": "refresh_token",
            "refresh_token": REFRESH_TOKEN
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    r.raise_for_status()
    j = r.json()
    return j["id_token"], j["user_id"], int(j["expires_in"])

class TokenManager:
    def __init__(self):
        self.token = None
        self.uid = None
        self.expiry = 0

    async def get(self, client):
        if not self.token or time.time() >= self.expiry:
            self.token, self.uid, ttl = await get_id_token(client)
            self.expiry = time.time() + ttl - 30
            log(f"[AUTH] Token refreshed (valid ~{ttl//60} min)")
        return self.token, self.uid

# ---------------- HASH (FAIRBID) ---------------- #

def build_hash_payload(user_id, url):
    global _last_timestamp

    now = int(time.time())
    if now <= _last_timestamp:
        now = _last_timestamp + 1
    _last_timestamp = now

    ts = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{url}{ts}{SALT}"

    return json.dumps(
        {
            "user_id": user_id,
            "timestamp": now,
            "hash_value": hashlib.sha512(raw.encode()).hexdigest(),
        },
        separators=(",", ":"),
    )

# ---------------- ENCRYPTION ---------------- #

def encrypt_offer(offer_id):
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    raw = json.dumps({"offerId": offer_id}, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(pad(raw, AES.block_size))
    return {"data": {"data": base64.b64encode(enc).decode()}}

# ---------------- FIRESTORE ---------------- #

async def get_super_offer(client, token, uid):
    try:
        r = await client.post(
            f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}"
            f"/databases/(default)/documents/users/{uid}:runQuery",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "structuredQuery": {
                    "from": [{"collectionId": "superOffers"}],
                    "where": {
                        "fieldFilter": {
                            "field": {"fieldPath": "status"},
                            "op": "NOT_EQUAL",
                            "value": {"stringValue": "COMPLETED"}
                        }
                    },
                    "limit": 1
                }
            }
        )

        for item in r.json():
            doc = item.get("document")
            if not doc:
                continue

            f = doc["fields"]
            offer_id = f["offerId"]["stringValue"]

            if offer_id in _processed_offers:
                return None

            return {
                "offerId": offer_id,
                "reward": int(f.get("rewardAmount", {}).get("integerValue", 0)),
                "fees": int(f.get("fees", {}).get("integerValue", 0)),
            }
    except Exception as e:
        log(f"[FIRESTORE] Error getting offer: {e}")
    
    return None

async def get_boosts(client, token, uid):
    try:
        r = await client.get(
            f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}"
            f"/databases/(default)/documents/users/{uid}?mask.fieldPaths=boosts",
            headers={"Authorization": f"Bearer {token}"}
        )

        if r.status_code != 200:
            return 0

        return int(
            r.json()
            .get("fields", {})
            .get("boosts", {})
            .get("integerValue", 0)
        )
    except Exception:
        return 0

# ---------------- FAIRBID (SILENT) ---------------- #

async def run_fairbid(client, cfg):
    try:
        r = await client.post(f"{BASE_URL}?spotId={SPOT_ID}", content=cfg["payload"])
        if r.status_code >= 400:
            return

        text = r.text
        
        # Parse impression URL
        try:
            if "impression" in text and 'impression":"' in text:
                parts = text.split('impression":"')
                if len(parts) > 1:
                    impression_url = parts[1].split('"')[0]
                    if impression_url.startswith('http'):
                        await client.get(impression_url)
        except Exception:
            pass
        
        # Parse completion URL
        try:
            if "completion" in text and 'completion":"' in text:
                parts = text.split('completion":"')
                if len(parts) > 1:
                    comp = parts[1].split('"')[0]
                    if comp.startswith('http'):
                        await client.post(comp, content=build_hash_payload(cfg["user_id"], comp))
        except Exception:
            pass
            
    except Exception:
        pass

# ---------------- UNLOCK / CLAIM ---------------- #

async def call_fn(client, token, name, offer_id):
    try:
        r = await client.post(
            f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/{name}",
            headers={"Authorization": f"Bearer {token}"},
            json=encrypt_offer(offer_id)
        )
        return r.json()
    except Exception:
        return {}

async def unlock_and_claim(client, token, offer):
    unlock = await call_fn(client, token, "superOffer_unlock", offer["offerId"])
    if unlock.get("result", {}).get("status") != "SUCCESS":
        return False

    claim = await call_fn(client, token, "superOffer_claim", offer["offerId"])
    return claim.get("result", {}).get("status") == "SUCCESS"

# ---------------- MAIN LOOP ---------------- #

async def bot_loop():
    """Main bot logic"""
    client = await create_client()
    
    try:
        cfg = await load_config(client)
        tm = TokenManager()

        log("[BOT] Starting optimized async bot with HTTP/2 and encryption")
        log(f"[BOT] User ID: {cfg['user_id']}")

        while True:
            try:
                token, uid = await tm.get(client)

                offer = await get_super_offer(client, token, uid)
                if not offer:
                    await asyncio.sleep(5)
                    continue

                log(f"[OFFER] Found offer {offer['offerId']} - Reward: {offer['reward']}, Fees: {offer['fees']}")
                
                target = offer["fees"] + 1

                while True:
                    boosts = await get_boosts(client, token, uid)
                    if boosts >= target:
                        break
                    await run_fairbid(client, cfg)
                    await asyncio.sleep(0.3)

                if await unlock_and_claim(client, token, offer):
                    log(
                        f"✅ [CLAIMED] Offer: {offer['offerId']} "
                        f"| Reward: {offer['reward']} | Fees: {offer['fees']}"
                    )
                else:
                    log(f"❌ [FAILED] Could not claim offer {offer['offerId']}")

                _processed_offers.add(offer["offerId"])
                await asyncio.sleep(1)

            except Exception as e:
                log(f"[ERROR] Bot loop error: {e}")
                await asyncio.sleep(10)

    except Exception as e:
        log(f"[FATAL] Bot initialization failed: {e}")
        raise
    finally:
        await client.aclose()

async def main():
    """Run both HTTP server and bot loop"""
    log("=" * 60)
    log("🚀 RENDER BOT STARTING")
    log("=" * 60)
    
    await start_http_server()
    await bot_loop()

if __name__ == "__main__":
    asyncio.run(main())
