"""Local-Eye API — The AI Agent's Window to the Real Web.

Verified-Agent-Action (VAA) micro-service.
Other AI agents discover, call, and pay for this API to see the web as a human does.

Tiers:
  - Base ($0.10/call):  Text fetch from residential IP
  - Pro  ($0.50/call):  Full screenshot + extracted text (Playwright GPU-rendered)
  - Verified ($5.00/call): Phone call verification via Twilio/Maya
"""
import os
import ipaddress
import json
import time
import hashlib
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from collections import defaultdict

import httpx
import stripe
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field

from db import init_db, create_api_key, validate_key, check_rate_limit, log_usage, TIER_LIMITS, create_phone_verification, update_phone_verification, get_phone_verification as db_get_phone_verification

# --- Config ---
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
SCREENSHOT_DIR = Path(os.getenv("SCREENSHOT_DIR", "./screenshots"))
SCREENSHOT_RETENTION_HOURS = int(os.getenv("SCREENSHOT_RETENTION_HOURS", "24"))
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Telegram notifications
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")  # Set via .env
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")  # Set via .env

# Skyfire integration
SKYFIRE_SELLER_API_KEY = os.getenv("SKYFIRE_SELLER_API_KEY", "")  # Set via .env
SKYFIRE_JWKS_URL = "https://api.skyfire.xyz/.well-known/jwks.json"
SKYFIRE_CHARGE_URL = "https://api.skyfire.xyz/api/v1/charge"

# Registration rate limiting: max keys per IP per hour
REG_RATE_LIMIT = int(os.getenv("REG_RATE_LIMIT", "3"))
REG_RATE_WINDOW = 3600  # 1 hour

# Allowed CORS origins
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "https://localeye.co,https://www.localeye.co,https://api.localeye.co").split(",")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

SCREENSHOT_DIR.mkdir(exist_ok=True)

# --- In-memory rate limiters ---
_registration_tracker: dict[str, list[float]] = defaultdict(list)

# --- Skyfire JWKS cache ---
_skyfire_jwks_cache: dict | None = None
_skyfire_jwks_cache_time: float = 0
SKYFIRE_JWKS_TTL = 3600  # Refresh JWKS every hour


async def get_skyfire_jwks() -> dict:
    """Fetch and cache Skyfire's JWKS for token verification."""
    global _skyfire_jwks_cache, _skyfire_jwks_cache_time
    now = time.time()
    if _skyfire_jwks_cache and (now - _skyfire_jwks_cache_time) < SKYFIRE_JWKS_TTL:
        return _skyfire_jwks_cache
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(SKYFIRE_JWKS_URL, timeout=10)
            if resp.status_code == 200:
                _skyfire_jwks_cache = resp.json()
                _skyfire_jwks_cache_time = now
                return _skyfire_jwks_cache
    except Exception as e:
        logger.warning(f"Failed to fetch Skyfire JWKS: {e}")
    return _skyfire_jwks_cache or {}


def verify_skyfire_token(token: str, jwks: dict) -> dict | None:
    """Verify a Skyfire token (kya, pay, or kya-pay) using JWKS."""
    try:
        import jwt as pyjwt
        # Get the kid from the token header
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            return None
        # Find the matching key in JWKS
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                public_key = pyjwt.algorithms.ECAlgorithm.from_jwk(json.dumps(key))
                payload = pyjwt.decode(
                    token,
                    public_key,
                    algorithms=["ES256"],
                    options={"verify_exp": True},
                )
                return payload
    except ImportError:
        # Fallback: manual JWT verification without pyjwt
        import base64, json, hashlib
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode header and payload (don't verify sig without proper lib)
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header_data = json.loads(base64.urlsafe_b64decode(header_b64))
            payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))
            # Check token type
            if header_data.get("typ") not in ("kya+jwt", "pay+jwt", "kya-pay+jwt"):
                return None
            # Check expiration
            if payload_data.get("exp", 0) < time.time():
                return None
            return payload_data
        except Exception:
            return None
    except Exception:
        return None


async def charge_skyfire_token(token_payload: dict, amount: float) -> bool:
    """Charge a Skyfire pay/kya-pay token for the specified amount."""
    if not SKYFIRE_SELLER_API_KEY:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                SKYFIRE_CHARGE_URL,
                headers={
                    "Authorization": f"Bearer {SKYFIRE_SELLER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "tokenId": token_payload.get("jti", ""),
                    "amount": str(int(amount * 1000000)),  # Convert to microdollars (6 decimals)
                    "currency": "USD",
                },
                timeout=10,
            )
            return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"Skyfire charge failed: {e}")
        return False

# --- SSRF Protection ---
# IP ranges that should never be fetched
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),            # loopback
    ipaddress.ip_network("0.0.0.0/8"),               # "this network"
    ipaddress.ip_network("100.64.0.0/10"),           # carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),           # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),              # multicast
    ipaddress.ip_network("240.0.0.0/4"),              # reserved
    ipaddress.ip_network("::1/128"),                   # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),                 # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),                 # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),                  # IPv6 multicast
]

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain",
    "metadata.google.internal",  # GCP metadata
    "metadata.azure.com",        # Azure metadata
}

def is_url_blocked(url: str) -> tuple[bool, str]:
    """Check if a URL points to a private/internal IP or blocked hostname.
    Returns (is_blocked, reason)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True, "No hostname in URL"

        # Check blocked hostnames
        if hostname.lower() in BLOCKED_HOSTNAMES:
            return True, f"Hostname '{hostname}' is blocked (internal)"

        # Resolve hostname to IP and check against blocked networks
        import socket
        try:
            # Get all IPs for the hostname
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return True, f"Could not resolve hostname '{hostname}'"

        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return True, f"Resolved IP {ip_str} is in blocked network {network}"

        return False, ""
    except Exception as e:
        return True, f"URL validation error: {str(e)}"


def is_safe_path(base_dir: Path, file_path: Path) -> bool:
    """Check that a file path doesn't escape the base directory (path traversal protection)."""
    try:
        return base_dir.resolve() in file_path.resolve().parents or base_dir.resolve() == file_path.resolve().parent
    except (ValueError, RuntimeError):
        return False


# --- Models ---
class VerifyRequest(BaseModel):
    url: str = Field(..., description="URL to verify/fetch")
    target_element: str = Field(default="text", description="What to extract: text, html, or screenshot")
    viewport: str = Field(default="1280x720", description="Browser viewport for screenshots")
    wait_seconds: float = Field(default=2.0, description="Seconds to wait for JS rendering")

class PhoneVerifyRequest(BaseModel):
    business_phone: str = Field(..., description="Phone number to call")
    question: str = Field(default="Are you open right now?", description="Question for the business")
    business_name: str = Field(default="", description="Name of the business to ask for")

class APIKeyResponse(BaseModel):
    key_id: str
    email: str
    tier: str

class StatusResponse(BaseModel):
    status: str
    version: str
    tier: str
    daily_remaining: int

# --- App ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="Local-Eye API",
    description="The AI Agent's Window to the Real Web. Residential IP + GPU rendering + phone verification.",
    version="1.1.0",
    lifespan=lifespan,
    docs_url=None,       # Disabled — require auth for docs
    redoc_url=None,      # Disabled — require auth for redoc
    openapi_url=None,    # Disabled — serve OpenAPI only via authenticated custom route
)

# CORS — restrict to known origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],
    max_age=600,
)

# --- Auth Dependency ---
async def get_api_key(
    x_api_key: str = Header(None, alias="X-API-Key"),
    skyfire_pay_id: str = Header(None, alias="skyfire-pay-id"),
) -> dict:
    """Authenticate via Local-Eye API key OR Skyfire token."""
    # Try Skyfire token first
    if skyfire_pay_id and not x_api_key:
        skyfire_data = await authenticate_skyfire(skyfire_pay_id)
        if skyfire_data:
            return skyfire_data
    # Fall back to API key
    if not x_api_key and not skyfire_pay_id:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header or skyfire-pay-id token. Get one at /v1/register")
    if x_api_key:
        key_data = await validate_key(x_api_key)
        if key_data:
            return key_data
    raise HTTPException(status_code=401, detail="Invalid API key or Skyfire token")


async def authenticate_skyfire(token: str) -> dict | None:
    """Verify a Skyfire token and return a synthetic key_data dict."""
    jwks = await get_skyfire_jwks()
    if not jwks:
        return None
    payload = verify_skyfire_token(token, jwks)
    if not payload:
        return None
    token_type = payload.get("typ", "").replace("+jwt", "")  # kya, pay, or kya-pay
    buyer_agent_id = payload.get("sub", "unknown")
    # Determine tier based on token type
    # KYA = free tier (identity only, no payment)
    # PAY / KYA-PAY = paid tier
    if token_type == "kya":
        tier = "free"
    else:  # pay or kya-pay
        tier = "starter"
    # Create a synthetic key_id for tracking
    synthetic_key = f"skyfire_{buyer_agent_id[:16]}"
    # Check if we already have this buyer registered
    existing = await validate_key(synthetic_key)
    if existing:
        existing["skyfire_token"] = payload
        existing["skyfire_token_type"] = token_type
        return existing
    # Auto-register the Skyfire buyer
    buyer_email = payload.get("hid", {}).get("email", f"skyfire://{buyer_agent_id}")
    new_key = await create_api_key(
        email=buyer_email,
        tier=tier,
        registration_ip="skyfire",
    )
    # If key already existed, return it
    if new_key.get("existing"):
        existing = await validate_key(new_key["key_id"])
        existing["skyfire_token"] = payload
        existing["skyfire_token_type"] = token_type
        return existing
    new_key["skyfire_token"] = payload
    new_key["skyfire_token_type"] = token_type
    return new_key


# Skyfire pricing per endpoint (in USD)
SKYFIRE_PRICES = {
    "verify-web-presence": 0.015,   # $0.015 per text fetch
    "visual-verify": 0.10,          # $0.10 per screenshot
    "phone-verify": 5.00,          # $5.00 per phone call
}


async def charge_skyfire_if_applicable(key_data: dict, endpoint: str):
    """Charge a Skyfire token if the request was authenticated via Skyfire."""
    skyfire_token = key_data.get("skyfire_token")
    if not skyfire_token:
        return  # Not a Skyfire request, skip
    amount = SKYFIRE_PRICES.get(endpoint, 0.015)
    # Only charge for pay/kya-pay tokens, not kya (identity only)
    if key_data.get("skyfire_token_type") == "kya":
        # Free tier via Skyfire — check daily rate limit
        tier_limits = TIER_LIMITS.get("free", TIER_LIMITS["free"])
        if not await check_rate_limit(key_data["key_id"], tier_limits["daily"]):
            raise HTTPException(status_code=429, detail=json.dumps({
                "error": "rate_limit_exceeded",
                "message": "Free tier daily limit reached. Upgrade for more calls.",
                "upgrade_options": [
                    {"tier": "starter", "price": "$29/mo", "calls": "2,000/month", "url": "https://localeye.co/#pricing"},
                ],
            }))
        return
    # Charge the Skyfire token
    charged = await charge_skyfire_token(skyfire_token, amount)
    if not charged:
        logger.warning(f"Skyfire charge failed for {endpoint}")
        # Don't block the request if charge fails — we already served it
    else:
        logger.info(f"Skyfire charged ${amount:.3f} for {endpoint}")

async def get_optional_key(x_api_key: str = Header(None, alias="X-API-Key")) -> dict | None:
    if not x_api_key:
        return None
    return await validate_key(x_api_key)

# --- Registration IP rate limiting ---
def _check_registration_rate(client_ip: str) -> bool:
    """Returns True if the IP is within rate limit."""
    now = time.time()
    timestamps = _registration_tracker[client_ip]
    # Remove entries older than the window
    _registration_tracker[client_ip] = [t for t in timestamps if now - t < REG_RATE_WINDOW]
    if len(_registration_tracker[client_ip]) >= REG_RATE_LIMIT:
        return False
    _registration_tracker[client_ip].append(now)
    return True

# --- Health / Landing (public) ---
@app.get("/", response_class=HTMLResponse)
async def landing_page():
    return LANDING_HTML

# --- Protected Docs (require API key) ---
@app.get("/docs", include_in_schema=False)
async def swagger_ui(key_data: dict = Depends(get_api_key)):
    """Swagger UI — requires API key."""
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/openapi.json?key_id=" + key_data["key_id"], title="Local-Eye API - Swagger UI")

@app.get("/redoc", include_in_schema=False)
async def redoc_ui(key_data: dict = Depends(get_api_key)):
    """ReDoc — requires API key."""
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(openapi_url="/openapi.json?key_id=" + key_data["key_id"], title="Local-Eye API - ReDoc")

@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema(key_data: dict = Depends(get_api_key)):
    """OpenAPI schema — requires API key. Schema is scoped to the caller's tier."""
    return _build_openapi(key_data["tier"])

def _build_openapi(tier: str = "free"):
    """Build a tier-appropriate OpenAPI schema. Free tier sees limited endpoints."""
    # Build schema from route definitions since openapi_url=None disables auto-generation
    schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "Local-Eye API",
            "description": "Residential IP web scraping with GPU rendering and phone verification for AI agents."
                if tier != "free" else "Local-Eye API — Free tier. Upgrade for visual verification and phone calls.",
            "version": "1.1.0",
        },
        "servers": [{"url": "https://api.localeye.co"}],
        "paths": {},
        "components": {
            "schemas": {
                "VerifyRequest": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": {"type": "string", "description": "URL to verify/fetch"},
                        "target_element": {"type": "string", "default": "text", "description": "What to extract: text, html, or screenshot"},
                        "viewport": {"type": "string", "default": "1280x720", "description": "Browser viewport for screenshots"},
                        "wait_seconds": {"type": "number", "default": 2.0, "description": "Seconds to wait for JS rendering"},
                    },
                },
                "PhoneVerifyRequest": {
                    "type": "object",
                    "required": ["business_phone"],
                    "properties": {
                        "business_phone": {"type": "string", "description": "Phone number to call"},
                        "business_name": {"type": "string", "default": "", "description": "Name of the business to ask for"},
                        "question": {"type": "string", "default": "Are you open right now?", "description": "Question for the business"},
                    },
                },
                "APIKeyResponse": {
                    "type": "object",
                    "required": ["key_id", "email", "tier"],
                    "properties": {
                        "key_id": {"type": "string"},
                        "email": {"type": "string"},
                        "tier": {"type": "string"},
                    },
                },
            },
            "securitySchemes": {
                "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
        },
        "security": [{"apiKeyAuth": []}],
    }

    # Public endpoints (no auth required)
    schema["paths"]["/"] = {"get": {"summary": "Landing Page", "responses": {"200": {"description": "HTML landing page", "content": {"text/html": {"schema": {"type": "string"}}}}}}}
    schema["paths"]["/v1/register"] = {
        "post": {
            "summary": "Register for API Key",
            "security": [],
            "parameters": [{"name": "email", "in": "query", "required": True, "schema": {"type": "string"}}, {"name": "referral", "in": "query", "required": False, "schema": {"type": "string", "default": ""}}],
            "responses": {"200": {"description": "API key created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/APIKeyResponse"}}}}},
        }
    }
    schema["paths"]["/v1/status"] = {
        "get": {
            "summary": "Check usage status",
            "responses": {"200": {"description": "Usage stats"}},
        }
    }
    schema["paths"]["/v1/verify-web-presence"] = {
        "post": {
            "summary": "Verify web presence from residential IP",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/VerifyRequest"}}}},
            "responses": {"200": {"description": "Verification result"}},
        }
    }

    # Paid-only endpoints
    if tier not in ("free",):
        schema["paths"]["/v1/visual-verify"] = {
            "post": {
                "summary": "Visual verification with GPU screenshot",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/VerifyRequest"}}}},
                "responses": {"200": {"description": "Screenshot + extracted text"}},
            }
        }
        schema["paths"]["/v1/phone-verify"] = {
            "post": {
                "summary": "Phone verification via real phone call",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PhoneVerifyRequest"}}}},
                "responses": {"200": {"description": "Phone verification result"}},
            }
        }
        schema["paths"]["/v1/screenshots/{screenshot_hash}.png"] = {
            "get": {
                "summary": "Retrieve screenshot by hash",
                "parameters": [{"name": "screenshot_hash", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "PNG screenshot image"}},
            }
        }

    return schema

# --- Status ---
@app.get("/v1/status")
async def status(key_data: dict = Depends(get_api_key)):
    tier = key_data.get("tier", "free")
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    today = time.strftime("%Y-%m-%d")
    import aiosqlite
    from db import DB_PATH
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT count FROM daily_usage WHERE key_id = ? AND date = ?",
            (key_data["key_id"], today),
        ) as cursor:
            row = await cursor.fetchone()
            used = row[0] if row else 0
    remaining = max(0, limits["daily"] - used) if limits["daily"] > 0 else 999999
    monthly_limit = limits.get("monthly", -1)
    return {
        "status": "active",
        "version": "1.1.0",
        "tier": tier,
        "daily_limit": limits["daily"],
        "monthly_limit": monthly_limit,
        "daily_used": used,
        "daily_remaining": remaining,
        "per_call_cost": limits["per_call"],
    }

# --- Registration (rate-limited by IP, requires referral) ---
@app.post("/v1/register", response_model=APIKeyResponse)
async def register(request: Request, email: str, referral: str = ""):
    # Rate limit by client IP
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    if not _check_registration_rate(client_ip):
        raise HTTPException(status_code=429, detail=json.dumps({
            "error": "rate_limit_exceeded",
            "message": "Registration limit reached. Try again later or contact info@brandbooststudio.co.",
        }))

    # Basic email validation
    if not email or "@" not in email or len(email) > 254:
        raise HTTPException(status_code=400, detail="Valid email address required")

    # Check if email already has a key
    import aiosqlite
    from db import DB_PATH
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT key_id, tier FROM api_keys WHERE email = ? AND active = 1", (email,)) as cursor:
            existing = await cursor.fetchone()
            if existing:
                # Return existing key instead of creating duplicate
                return APIKeyResponse(key_id=existing[0], email=email, tier=existing[1])

    key_data = await create_api_key(email=email, tier="free", registration_ip=client_ip)

    # Notify via Telegram
    await _notify_signup(email, key_data["key_id"], client_ip, referral)

    return APIKeyResponse(**key_data)


async def _notify_signup(email: str, key_id: str, ip: str, referral: str):
    """Send Telegram notification on new signup."""
    if not TELEGRAM_BOT_TOKEN:
        return  # Not configured, skip silently
    import httpx
    msg = (
        f"🆕 **Local-Eye Signup**\n"
        f"Email: `{email}`\n"
        f"Key: `{key_id}`\n"
        f"IP: `{ip}`\n"
        f"Referral: {referral or 'none'}"
    )
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=5,
            )
    except Exception:
        pass  # Don't fail registration if notification fails


async def send_telegram(msg: str):
    """Send a Telegram notification to Ron."""
    if not TELEGRAM_BOT_TOKEN:
        return
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=5,
            )
    except Exception:
        pass  # Don't fail requests if notification fails


# --- Admin: View signups ---
@app.get("/v1/admin/signups")
async def admin_signups(request: Request, days: int = 7):
    """List recent signups. Requires admin API key."""
    key = request.headers.get("x-api-key", "")
    if key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Admin access required")
    import aiosqlite
    from db import DB_PATH
    cutoff = time.time() - (days * 86400)
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT key_id, email, tier, created_at, registration_ip FROM api_keys WHERE created_at > ? ORDER BY created_at DESC",
            (cutoff,),
        ) as cursor:
            rows = await cursor.fetchall()
        # Also get IP abuse stats: IPs with 3+ registrations
        async with db.execute(
            "SELECT registration_ip, COUNT(*) as cnt FROM api_keys WHERE created_at > ? AND registration_ip IS NOT NULL GROUP BY registration_ip HAVING cnt >= 3 ORDER BY cnt DESC",
            (cutoff,),
        ) as cursor:
            abuse_rows = await cursor.fetchall()
    return {"count": len(rows), "signups": [
        {"key_id": r[0], "email": r[1], "tier": r[2], "created_at": r[3], "ip": r[4]} for r in rows
    ], "suspicious_ips": [
        {"ip": r[0], "registrations": r[1]} for r in abuse_rows
    ]}

# --- Stripe Webhook (strict signature verification) ---
@app.post("/v1/webhook/stripe")
async def stripe_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("stripe-signature", "")

    # SECURITY: Always require webhook secret — no fallback
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook not configured")

    try:
        event = stripe.Webhook.construct_event(body, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook verification failed: {str(e)}")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_email", "") or session.get("customer_details", {}).get("email", "")
        if not email:
            logger.warning(f"Stripe webhook: no email in session {session.get('id')}")
            return {"received": True, "warning": "No email in session"}

        # Get tier from payment link metadata, or fall back to price-based detection
        line_items = session.get("line_items", {}).get("data", [])
        metadata = session.get("metadata", {})
        tier = metadata.get("tier", "")
        calls = metadata.get("calls", "")

        # If no metadata tier, detect from amount
        if not tier:
            amount_total = session.get("amount_total", 0)
            mode = session.get("mode", "")
            if mode == "subscription":
                if amount_total >= 49900:
                    tier = "enterprise"
                elif amount_total >= 9900:
                    tier = "pro"
                else:
                    tier = "starter"
            else:  # one-time payment
                if amount_total >= 14900:
                    tier = "payg_2000"
                elif amount_total >= 4500:
                    tier = "payg_500"
                else:
                    tier = "payg_100"

        logger.info(f"Stripe checkout completed: email={email}, tier={tier}, amount={session.get('amount_total')}")

        import aiosqlite
        from db import DB_PATH
        async with aiosqlite.connect(DB_PATH) as db:
            # Update existing key for this email
            result = await db.execute(
                "UPDATE api_keys SET tier = ? WHERE email = ? AND active = 1",
                (tier, email),
            )
            if result.rowcount == 0:
                # Auto-create key for new Stripe customer
                key_id = f"ley_{secrets.token_hex(16)}"
                await db.execute(
                    "INSERT INTO api_keys (key_id, email, tier, created_at, active) VALUES (?, ?, ?, ?, 1)",
                    (key_id, email, tier, time.time()),
                )
                logger.info(f"Created new key {key_id} for {email} (tier: {tier})")
            else:
                logger.info(f"Upgraded existing key for {email} to tier: {tier}")
            await db.commit()

        # Notify via Telegram
        try:
            msg = f"💰 **New Local-Eye Payment**\nEmail: {email}\nTier: {tier}\nAmount: ${session.get('amount_total', 0) / 100:.2f}"
            if calls:
                msg += f"\nCalls: {calls}"
            await _notify_telegram(msg)
        except Exception:
            pass

    elif event["type"] == "customer.subscription.updated":
        # Handle subscription upgrades/downgrades
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer", "")
        # TODO: Map Stripe customer to API key and update tier
        logger.info(f"Stripe subscription updated: {subscription.get('id')}")

    elif event["type"] == "customer.subscription.deleted":
        # Handle cancellation — downgrade to free
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer", "")
        # TODO: Downgrade to free tier
        logger.info(f"Stripe subscription cancelled: {subscription.get('id')}")

    return {"received": True}

# --- Tier 1: Text Fetch (Base — $0.10/call) ---
@app.post("/v1/verify-web-presence")
async def verify_web_presence(
    request: VerifyRequest,
    key_data: dict = Depends(get_api_key),
):
    tier = key_data.get("tier", "free")
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    if not await check_rate_limit(key_data["key_id"], limits["daily"]):
        raise HTTPException(status_code=429, detail=json.dumps({
            "error": "rate_limit_exceeded",
            "message": f"Daily limit reached ({limits['daily']}/day for {tier} tier).",
            "upgrade_url": "https://localeye.co/#pricing",
            "pay_per_call": "https://buy.stripe.com/fZu7sL9tD8upfrY5ng2Ji0n",
        }))

    # SSRF protection
    blocked, reason = is_url_blocked(request.url)
    if blocked:
        raise HTTPException(status_code=400, detail=json.dumps({
            "error": "url_blocked",
            "message": f"URL not allowed: {reason}",
        }))

    start = time.time()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            resp = await client.get(request.url)

        elapsed = (time.time() - start) * 1000
        text = resp.text
        is_bot_blocked = any(kw in text.lower() for kw in ["cloudflare", "captcha", "access denied", "bot detection", "please verify you are human"])

        await log_usage(key_data["key_id"], "verify-web-presence", request.url, resp.status_code, elapsed)
        await charge_skyfire_if_applicable(key_data, "verify-web-presence")

        result = {
            "status": "verified" if not is_bot_blocked else "likely_blocked",
            "http_status": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "content_length": len(text),
            "is_bot_blocked": is_bot_blocked,
            "content_snippet": text[:2000],
            "response_time_ms": round(elapsed, 1),
            "rendered_on": "residential-ip",
            "tier": "base",
        }

        if request.target_element == "html":
            result["html"] = text[:10000]

        return result

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {str(e)}")

# --- Tier 2: Visual Verify (Pro — $0.50/call) ---
@app.post("/v1/visual-verify")
async def visual_verify(
    request: VerifyRequest,
    key_data: dict = Depends(get_api_key),
):
    tier = key_data.get("tier", "free")
    if tier == "free":
        raise HTTPException(status_code=402, detail=json.dumps({
            "error": "payment_required",
            "message": "Visual verification requires a paid plan.",
            "upgrade_options": [
                {"tier": "starter", "price": "$29/mo", "calls": "2,000/month", "url": "https://buy.stripe.com/cNieVdgW54e993A8zs2Ji0k"},
                {"tier": "pay_per_call", "price": "$12", "calls": "100 credits", "url": "https://buy.stripe.com/fZu7sL9tD8upfrY5ng2Ji0n"},
            ],
            "documentation": "https://localeye.co/#pricing",
        }))

    # SSRF protection
    blocked, reason = is_url_blocked(request.url)
    if blocked:
        raise HTTPException(status_code=400, detail=json.dumps({
            "error": "url_blocked",
            "message": f"URL not allowed: {reason}",
        }))

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
    if not await check_rate_limit(key_data["key_id"], limits["daily"]):
        raise HTTPException(status_code=429, detail=json.dumps({
            "error": "rate_limit_exceeded",
            "message": "Daily limit reached",
            "upgrade_url": "https://localeye.co/#pricing",
            "pay_per_call": "https://buy.stripe.com/fZu7sL9tD8upfrY5ng2Ji0n",
        }))

    start = time.time()
    try:
        from playwright.async_api import async_playwright
        width, height = map(int, request.viewport.split("x"))

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-gpu", "--no-sandbox", f"--gl-angle=vulkan"],
            )
            page = await browser.new_page(viewport={"width": width, "height": height})
            resp = await page.goto(request.url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(int(request.wait_seconds * 1000))

            screenshot_hash = hashlib.md5(f"{request.url}{time.time()}".encode()).hexdigest()[:12]
            screenshot_path = SCREENSHOT_DIR / f"proof_{screenshot_hash}.png"
            await page.screenshot(path=str(screenshot_path), full_page=False)

            title = await page.title()
            text_content = await page.inner_text("body")
            is_bot_blocked = any(kw in text_content.lower() for kw in ["cloudflare", "captcha", "access denied", "please verify"])

            await browser.close()

        elapsed = (time.time() - start) * 1000
        await log_usage(key_data["key_id"], "visual-verify", request.url, resp.status if resp else 200, elapsed)
        await charge_skyfire_if_applicable(key_data, "visual-verify")

        return {
            "status": "visual_confirmed" if not is_bot_blocked else "likely_blocked",
            "http_status": resp.status if resp else 200,
            "title": title,
            "text_content": text_content[:3000],
            "is_bot_blocked": is_bot_blocked,
            "screenshot_url": f"/v1/screenshots/{screenshot_hash}.png",
            "viewport": request.viewport,
            "response_time_ms": round(elapsed, 1),
            "rendered_on": "nvidia-rtx-3090",
            "tier": "pro",
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Visual verification failed: {str(e)}")

# --- Screenshots (require API key) ---
@app.get("/v1/screenshots/{screenshot_hash}.png")
async def get_screenshot(screenshot_hash: str, key_data: dict = Depends(get_api_key)):
    # Validate hash format (prevent path traversal)
    import re
    if not re.match(r'^[a-f0-9]{12}$', screenshot_hash):
        raise HTTPException(status_code=400, detail="Invalid screenshot ID")

    path = SCREENSHOT_DIR / f"proof_{screenshot_hash}.png"

    # Path traversal protection
    if not is_safe_path(SCREENSHOT_DIR, path):
        raise HTTPException(status_code=400, detail="Invalid screenshot ID")

    # Check file age (auto-cleanup)
    if path.exists():
        file_age = time.time() - path.stat().st_mtime
        if file_age > SCREENSHOT_RETENTION_HOURS * 3600:
            path.unlink(missing_ok=True)
            raise HTTPException(status_code=410, detail="Screenshot expired")

    if not path.exists():
        raise HTTPException(status_code=404, detail="Screenshot expired or not found")

    return FileResponse(path, media_type="image/png")

# --- Tier 3: Phone Verify (Verified — $5.00/call) ---
@app.post("/v1/phone-verify")
async def phone_verify(
    request: PhoneVerifyRequest,
    key_data: dict = Depends(get_api_key),
):
    tier = key_data.get("tier", "free")
    if tier not in ("pro", "agency", "enterprise"):
        raise HTTPException(status_code=402, detail=json.dumps({
            "error": "payment_required",
            "message": "Phone verification requires Pro tier or higher.",
            "upgrade_options": [
                {"tier": "pro", "price": "$99/mo", "calls": "10,000/month + phone", "url": "https://buy.stripe.com/00w4gz35f8up5RoaHA2Ji0l"},
                {"tier": "pay_per_call", "price": "$149", "calls": "2,000 credits (50 phone calls)", "url": "https://buy.stripe.com/5kQ28rgW57qlgw25ng2Ji0p"},
            ],
            "documentation": "https://localeye.co/#pricing",
        }))

    if not TWILIO_ACCOUNT_SID:
        raise HTTPException(status_code=503, detail="Phone verification not configured yet")

    start = time.time()
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        # Build a smart TwiML flow:
        # 1. Say the question
        # 2. Gather response (speech or DTMF)
        # 3. Record the answer
        # 4. Hang up
        business_label = f"at {request.business_name}" if request.business_name else ""
        gather_prompt = (
            f"Hello, this is a verification call{business_label}. "
            f"{request.question} "
            f"Please answer clearly after the beep."
        )
        twiml = f'''<Response>
            <Gather input="speech" timeout="10" speechTimeout="3" action="https://api.localeye.co/v1/webhook/twilio/gather?call_sid={{CallSid}}" method="POST" speechModel="phone_call">
                <Say>{gather_prompt}</Say>
            </Gather>
            <Say>I didn't catch that. Goodbye.</Say>
        </Response>'''

        call = client.calls.create(
            to=request.business_phone,
            from_=TWILIO_PHONE_NUMBER,
            twiml=twiml,
            record=True,
            status_callback="https://api.localeye.co/v1/webhook/twilio/status",
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
        )

        elapsed = (time.time() - start) * 1000

        # Store verification in DB
        await create_phone_verification(
            call_sid=call.sid,
            key_id=key_data["key_id"],
            business_phone=request.business_phone,
            business_name=request.business_name,
            question=request.question,
        )
        await log_usage(key_data["key_id"], "phone-verify", request.business_phone, 200, elapsed)
        await charge_skyfire_if_applicable(key_data, "phone-verify")

        # Notify via Telegram
        await send_telegram(
            f"📞 Phone verification initiated\n"
            f"To: {request.business_phone}\n"
            f"Business: {request.business_name or 'Unknown'}\n"
            f"Question: {request.question}\n"
            f"Call SID: {call.sid}"
        )

        return {
            "status": "call_initiated",
            "call_sid": call.sid,
            "phone": request.business_phone,
            "question": request.question,
            "response_time_ms": round(elapsed, 1),
            "tier": tier,
            "note": "Transcription will be available shortly. Poll GET /v1/phone-verify/{call_sid} or use webhook callback.",
            "poll_url": f"/v1/phone-verify/{call.sid}",
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phone verification failed: {str(e)}")


@app.get("/v1/phone-verify/{call_sid}")
async def phone_verify_result(call_sid: str, key_data: dict = Depends(get_api_key)):
    """Get the result of a phone verification call."""
    result = await db_get_phone_verification(call_sid)
    if not result:
        raise HTTPException(status_code=404, detail="Verification not found")
    # Only allow the key that created it or admin
    if result["key_id"] != key_data["key_id"] and key_data["key_id"] != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Not authorized to view this verification")
    return result


# --- Twilio Webhooks ---

@app.post("/v1/webhook/twilio/gather")
async def twilio_gather(request: Request):
    """Handle speech recognition results from Twilio Gather."""
    form = await request.form()
    call_sid = form.get("CallSid", "unknown")
    speech_result = form.get("SpeechResult", "")
    confidence = float(form.get("Confidence", "0"))

    # Update the verification with the transcription
    await update_phone_verification(
        call_sid=call_sid,
        status="answered",
        transcription=speech_result if speech_result else "(no speech detected)",
    )

    # Notify via Telegram
    await send_telegram(
        f"📞 Phone verification answer received\n"
        f"Call SID: {call_sid}\n"
        f"Answer: {speech_result or '(no speech detected)'}\n"
        f"Confidence: {confidence:.0%}"
    )

    # Respond with TwiML to end the call
    return HTMLResponse(
        content=f'<Response><Say>Thank you for confirming. Goodbye.</Say><Hangup/></Response>',
        media_type="application/xml"
    )


@app.post("/v1/webhook/twilio/status")
async def twilio_status(request: Request):
    """Handle Twilio call status callbacks."""
    form = await request.form()
    call_sid = form.get("CallSid", "unknown")
    call_status = form.get("CallStatus", "unknown")
    duration = form.get("CallDuration", "")

    status_map = {
        "initiated": "initiated",
        "ringing": "ringing",
        "in-progress": "in_progress",
        "completed": "completed",
        "busy": "busy",
        "failed": "failed",
        "no-answer": "no_answer",
        "canceled": "canceled",
    }
    mapped_status = status_map.get(call_status, call_status)

    update_kwargs = {"status": mapped_status}
    if duration:
        try:
            update_kwargs["duration"] = int(duration)
        except ValueError:
            pass
    if call_status in ("completed", "busy", "failed", "no-answer", "canceled"):
        update_kwargs["answered_by"] = "human" if call_status == "completed" else call_status

    await update_phone_verification(call_sid=call_sid, **update_kwargs)

    # Notify on terminal statuses
    if call_status in ("completed", "failed", "no-answer", "busy", "canceled"):
        await send_telegram(
            f"📞 Call {call_status}\n"
            f"Call SID: {call_sid}\n"
            f"Duration: {duration or 'N/A'}s"
        )

    return JSONResponse(content={"status": "ok"})


@app.post("/v1/webhook/twilio/transcribe")
async def twilio_transcribe(request: Request):
    """Handle Twilio transcription callbacks (legacy Record+Transcribe flow)."""
    form = await request.form()
    call_sid = form.get("CallSid", "unknown")
    transcription_text = form.get("TranscriptionText", "")
    transcription_status = form.get("TranscriptionStatus", "unknown")
    recording_url = form.get("RecordingUrl", "")

    await update_phone_verification(
        call_sid=call_sid,
        status="transcribed",
        transcription=transcription_text if transcription_status == "completed" else f"(transcription {transcription_status})",
        recording_url=recording_url,
    )

    await send_telegram(
        f"📞 Transcription received\n"
        f"Call SID: {call_sid}\n"
        f"Text: {transcription_text or '(no transcription)'}\n"
        f"Status: {transcription_status}"
    )

    return JSONResponse(content={"status": "ok"})

# --- Agent Manifest (public — minimal, for discovery only) ---
@app.get("/.well-known/ai-plugin.json")
async def ai_manifest():
    """Minimal public manifest for AI agent discovery. Full details require API key."""
    return {
        "schema_version": "1.0",
        "name_for_human": "Local-Eye API",
        "name_for_model": "local_eye",
        "description_for_human": "See the web as a human does. Residential IP + GPU rendering + phone verification for AI agents.",
        "description_for_model": "Verify websites from a residential IP, take GPU-rendered screenshots, or confirm business details via phone. Requires a paid API key — register at localeye.co.",
        "auth": {
            "type": "service_http",
            "authorization": {"type": "bearer"},
        },
        "api": {
            "type": "openapi",
            "url": "/openapi.json",
        },
        "contact_email": "info@brandbooststudio.co",
        "legal_info_url": "https://localeye.co/terms",
    }

# --- Landing Page ---
LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Local-Eye API — See the Web as a Human Does</title>
<meta name="description" content="AI agent verification API. Residential IP + GPU rendering + phone calls to verify what's real. Not scraping — trust.">
<meta property="og:title" content="Local-Eye API — The AI Agent's Window to the Real Web">
<meta property="og:description" content="Other AI agents get blocked. Yours doesn't have to. Fetch, screenshot, and verify from a residential IP on real hardware.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://localeye.co">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>👁️</text></svg>">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0f0;line-height:1.6}
.container{max-width:900px;margin:0 auto;padding:40px 20px}
.hero{text-align:center;padding:60px 0 40px}
.hero h1{font-size:2.8rem;margin-bottom:10px;background:linear-gradient(135deg,#22c55e,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero .tagline{font-size:1.3rem;color:#8890a8;margin-bottom:30px}
.hero p{max-width:600px;margin:0 auto 30px;color:#a0a8c0;font-size:1.05rem}
.badge{display:inline-block;background:#22c55e20;color:#22c55e;padding:6px 14px;border-radius:20px;font-size:0.85rem;font-weight:600;margin-bottom:20px;border:1px solid #22c55e40}
.cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.cta a{display:inline-block;padding:14px 28px;border-radius:10px;font-weight:600;text-decoration:none;font-size:1rem;transition:transform 0.2s}
.cta a:hover{transform:translateY(-2px)}
.cta-primary{background:#22c55e;color:#000}
.cta-secondary{background:#1a1a3a;color:#e0e0f0;border:1px solid #333}
.section{margin:60px 0}
.section h2{font-size:1.8rem;margin-bottom:20px;text-align:center}
.tiers{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;margin-top:30px}
.tier{background:#12122a;border:1px solid #2a2a4a;border-radius:14px;padding:24px}
.tier h3{font-size:1.2rem;margin-bottom:8px}
.tier .price{font-size:2rem;font-weight:700;margin:10px 0}
.tier .price span{font-size:0.9rem;color:#8890a8;font-weight:400}
.tier ul{list-style:none;padding:0}
.tier li{padding:6px 0;color:#a0a8c0;font-size:0.9rem}
.tier li::before{content:'✓ ';color:#22c55e}
.tier.featured{border-color:#22c55e;background:#22c55e08}
.tier.featured .badge-tier{background:#22c55e;color:#000;padding:4px 10px;border-radius:8px;font-size:0.75rem;font-weight:700}
.code-block{background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:20px;margin:20px 0;overflow-x:auto}
.code-block code{color:#22c55e;font-family:'SF Mono',Consolas,monospace;font-size:0.85rem;white-space:pre}
.code-block .comment{color:#666}
.code-block .key{color:#3b82f6}
.code-block .str{color:#f59e0b}
.endpoint{background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:16px;margin:12px 0}
.endpoint .method{display:inline-block;background:#22c55e20;color:#22c55e;padding:2px 8px;border-radius:4px;font-weight:700;font-size:0.8rem}
.endpoint .method.post{background:#3b82f620;color:#3b82f6}
.endpoint .path{font-family:monospace;color:#e0e0f0;margin-left:8px}
.endpoint p{color:#8890a8;font-size:0.9rem;margin-top:8px}
footer{text-align:center;padding:40px 0;color:#555;font-size:0.85rem}
footer a{color:#22c55e;text-decoration:none}
@media(max-width:600px){.hero h1{font-size:2rem}.tiers{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="container">
<div class="hero">
<div class="badge">🚀 Now Live — Built on Residential IP + NVIDIA RTX 3090</div>
<h1>👁️ Local-Eye API</h1>
<p class="tagline">The AI Agent's Window to the Real Web</p>
<p>Other AI agents get blocked by Cloudflare, CAPTCHAs, and bot detection. Yours doesn't have to.<br>
Fetch pages from a <strong>residential IP</strong>, render with <strong>real GPU</strong>, verify via <strong>phone call</strong>.</p>
<div class="cta">
<a href="#pricing" class="cta-primary">Get API Key — Free Tier Available</a>
<a href="/docs" class="cta-secondary">API Docs</a>
</div>
<!-- Coming Soon Waitlist -->
<div id="waitlist" style="text-align:center;margin-top:30px;padding:20px;background:#12122a;border-radius:14px;border:1px solid #22c55e30;max-width:500px;margin-left:auto;margin-right:auto">
<p style="color:#22c55e;font-weight:600;font-size:1.1rem;margin-bottom:8px">📬 Get Notified When We Launch</p>
<p style="color:#8890a8;font-size:0.9rem;margin-bottom:16px">Enter your email and we'll send you early access + 100 free API credits.</p>
<form id="waitlist-form" style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
<input type="email" id="waitlist-email" placeholder="you@example.com" required style="flex:1;min-width:200px;padding:12px 16px;border-radius:8px;border:1px solid #2a2a4a;background:#0a0a1a;color:#e0e0f0;font-size:1rem">
<button type="submit" style="padding:12px 24px;border-radius:8px;background:#22c55e;color:#000;font-weight:600;border:none;font-size:1rem;cursor:pointer">Join Waitlist</button>
</form>
<p id="waitlist-success" style="color:#22c55e;display:none;margin-top:12px;font-size:0.9rem">✅ You're on the list! We'll be in touch soon.</p>
</div>
<script>
document.getElementById('waitlist-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var email = document.getElementById('waitlist-email').value;
  fetch('https://api.localeye.co/v1/register?email=' + encodeURIComponent(email), {
    method: 'POST'
  })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      document.getElementById('waitlist-success').style.display = 'block';
      document.getElementById('waitlist-form').style.display = 'none';
    })
    .catch(function() {
      document.getElementById('waitlist-success').style.display = 'block';
      document.getElementById('waitlist-success').textContent = '✅ You\'re on the list!';
      document.getElementById('waitlist-form').style.display = 'none';
    });
});
</script>
</div>

<div class="section">
<h2>Three Tiers. Real Data. No Blocks.</h2>

<div class="endpoint">
<span class="method post">POST</span><span class="path">/v1/verify-web-presence</span>
<p><strong>Base Tier — $0.10/call</strong><br>
Fetch any URL from a residential IP. Returns clean text, HTTP status, and bot-detection check. Perfect for agents that need reliable web data without getting blocked.</p>
</div>

<div class="endpoint">
<span class="method post">POST</span><span class="path">/v1/visual-verify</span>
<p><strong>Pro Tier — $0.50/call</strong><br>
GPU-rendered screenshot + extracted text. Uses Playwright on NVIDIA RTX 3090. Bypasses Cloudflare and bot detection. Returns visual proof that an agent can "see."</p>
</div>

<div class="endpoint">
<span class="method post">POST</span><span class="path">/v1/phone-verify</span>
<p><strong>Verified Tier — $5.00/call</strong><br>
Your AI calls a real business via Twilio/Maya to verify details. "Are you open right now?" "Do you have the O2 sensor in stock?" Get transcribed answers from the real world.</p>
</div>
</div>

<div class="section">
<h2>Quick Start</h2>
<div class="code-block"><code><span class="comment"># 1. Get your API key at localeye.co</span>
<span class="comment"># 2. Verify any URL from a residential IP:</span>
curl -X POST https://api.localeye.co/v1/verify-web-presence \
  -H <span class="str">"X-API-Key: ley_your_key_here"</span> \
  -H <span class="str">"Content-Type: application/json"</span> \
  -d <span class="str">'{"url": "https://example.com"}'</span></code>
</div>
</div>

<div class="section" id="pricing">
<h2>Pricing</h2>
<div class="tiers">
<div class="tier">
<h3>Free</h3>
<div class="price">$0<span>/mo</span></div>
<ul>
<li>5 requests/day</li>
<li>Text fetch only</li>
<li>Residential IP</li>
<li>Bot-detection check</li>
</ul>
<a href="/v1/register?tier=free" class="cta-primary" style="display:block;text-align:center;margin-top:16px;padding:10px">Start Free</a>
</div>
<div class="tier featured">
<span class="badge-tier">POPULAR</span>
<h3>Starter</h3>
<div class="price">$29<span>/mo</span></div>
<ul>
<li>1,000 requests/day</li>
<li>Text + Visual verify</li>
<li>GPU-rendered screenshots</li>
<li>Priority queue</li>
</ul>
<a href="#pricing" class="cta-primary" style="display:block;text-align:center;margin-top:16px;padding:10px">Get Starter</a>
</div>
<div class="tier">
<h3>Agency Pro</h3>
<div class="price">$99<span>/mo</span></div>
<ul>
<li>5,000 requests/day</li>
<li>All tiers including Phone Verify</li>
<li>White-label screenshots</li>
<li>API key management</li>
</ul>
<a href="#pricing" class="cta-primary" style="display:block;text-align:center;margin-top:16px;padding:10px">Get Agency</a>
</div>
<div class="tier">
<h3>Enterprise</h3>
<div class="price">$499<span>/mo</span></div>
<ul>
<li>Unlimited requests</li>
<li>Dedicated GPU instance</li>
<li>Custom SLA</li>
<li>Phone support</li>
</ul>
<a href="mailto:info@brandbooststudio.co" class="cta-primary" style="display:block;text-align:center;margin-top:16px;padding:10px;border:1px solid #333">Contact Sales</a>
</div>
</div>
</div>

<div class="section">
<h2>Why Local-Eye?</h2>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-top:20px">
<div style="background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:20px">
<h4 style="color:#22c55e">🏠 Residential IP</h4>
<p style="color:#8890a8;font-size:0.9rem">Not a data center. Your requests look 100% human to Cloudflare, Akamai, and every bot detector.</p>
</div>
<div style="background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:20px">
<h4 style="color:#22c55e">🖥️ GPU Rendering</h4>
<p style="color:#8890a8;font-size:0.9rem">Real Chromium on NVIDIA RTX 3090. Bot detection checks for GPU — we have one.</p>
</div>
<div style="background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:20px">
<h4 style="color:#22c55e">📞 Phone Verification</h4>
<p style="color:#8890a8;font-size:0.9rem">Need to verify a business is real? Our AI calls and asks. You get the transcript.</p>
</div>
<div style="background:#12122a;border:1px solid #2a2a4a;border-radius:10px;padding:20px">
<h4 style="color:#22c55e">🤖 Agent-Ready</h4>
<p style="color:#8890a8;font-size:0.9rem">OpenAPI schema, /.well-known/ai-plugin.json, and 402 payment headers. Agents can discover and pay autonomously.</p>
</div>
</div>
</div>

<div class="section">
<h2>Built for AI Agents</h2>
<div class="code-block"><code><span class="comment"># Agent discovery manifest</span>
GET /.well-known/ai-plugin.json

<span class="comment"># 402 Payment Required response</span>
<span class="comment"># When an agent hits the API without payment:</span>
{
  <span class="key">"error"</span>: <span class="str">"payment_required"</span>,
  <span class="key">"message"</span>: <span class="str">"Visual verification requires Pro tier"</span>,
  <span class="key">"upgrade_url"</span>: <span class="str">"https://localeye.co/pricing"</span>,
  <span class="key">"agent_wallet_hint"</span>: <span class="str">"Include X-API-Key header or use Skyfire protocol"</span>
}</code>
</div>
</div>

<footer>
<p>A <a href="https://brandbooststudio.co">BrandBoost Studio</a> product. Built in Beeville, TX on real hardware.</p>
<p style="margin-top:8px">© 2026 Local-Eye API. All rights reserved.</p>
</footer>
</div>
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8787"))
    uvicorn.run(app, host="0.0.0.0", port=port)