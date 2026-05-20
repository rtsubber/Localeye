"""Local-Eye API — Database models and API key management."""
import aiosqlite
import hashlib
import secrets
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "agent_check.db"

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    email TEXT,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    tier TEXT DEFAULT 'free',
    created_at REAL,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS suite_keys (
    suite_key TEXT PRIMARY KEY,
    localeye_key TEXT NOT NULL,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT,
    endpoint TEXT,
    url TEXT,
    status_code INTEGER,
    response_time_ms REAL,
    created_at REAL,
    FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
);

CREATE TABLE IF NOT EXISTS daily_usage (
    key_id TEXT,
    date TEXT,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (key_id, date)
);

CREATE TABLE IF NOT EXISTS phone_verifications (
    call_sid TEXT PRIMARY KEY,
    key_id TEXT,
    business_phone TEXT,
    business_name TEXT,
    question TEXT,
    status TEXT DEFAULT 'initiated',
    transcription TEXT,
    recording_url TEXT,
    duration INTEGER,
    answered_by TEXT,
    created_at REAL,
    completed_at REAL,
    FOREIGN KEY (key_id) REFERENCES api_keys(key_id)
);

CREATE TABLE IF NOT EXISTS scam_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    claimed_company TEXT,
    scam_score INTEGER,
    reporter_ip TEXT,
    reporter_key_id TEXT,
    reasons TEXT,
    created_at REAL
);
"""

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES)
        await db.commit()

async def create_api_key(email: str, tier: str = "free", stripe_customer_id: str = None, registration_ip: str = None) -> dict:
    key_id = f"ley_{secrets.token_hex(16)}"
    created_at = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        # Check for existing active key for this email
        async with db.execute(
            "SELECT key_id, tier FROM api_keys WHERE email = ? AND active = 1",
            (email,),
        ) as cursor:
            existing = await cursor.fetchone()
            if existing:
                return {"key_id": existing[0], "email": email, "tier": existing[1], "existing": True}
        await db.execute(
            "INSERT INTO api_keys (key_id, email, stripe_customer_id, tier, created_at, registration_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, email, stripe_customer_id, tier, created_at, registration_ip),
        )
        await db.commit()
    return {"key_id": key_id, "email": email, "tier": tier}

async def resolve_suite_key(key_id: str) -> str:
    """If key starts with suite_, look up the Local-Eye key. Otherwise return as-is."""
    if key_id.startswith("suite_"):
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT localeye_key FROM suite_keys WHERE suite_key = ?", (key_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return row[0]
        return None  # Invalid suite key
    return key_id


async def validate_key(key_id: str) -> dict | None:
    # Resolve suite keys first
    resolved = await resolve_suite_key(key_id)
    if resolved is None:
        return None  # Invalid suite key
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT key_id, email, tier, stripe_subscription_id, active FROM api_keys WHERE key_id = ?",
            (resolved,),
        ) as cursor:
            row = await cursor.fetchone()
            if row and row[4]:  # active
                return {"key_id": row[0], "email": row[1], "tier": row[2], "stripe_sub_id": row[3]}
    return None

async def check_rate_limit(key_id: str, daily_limit: int) -> bool:
    today = time.strftime("%Y-%m-%d")
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT count FROM daily_usage WHERE key_id = ? AND date = ?",
            (key_id, today),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                await db.execute(
                    "INSERT INTO daily_usage (key_id, date, count) VALUES (?, ?, 1)",
                    (key_id, today),
                )
                await db.commit()
                return True
            count = row[0]
            if count >= daily_limit:
                return False
            await db.execute(
                "UPDATE daily_usage SET count = count + 1 WHERE key_id = ? AND date = ?",
                (key_id, today),
            )
            await db.commit()
            return True

async def log_usage(key_id: str, endpoint: str, url: str, status_code: int, response_time_ms: float):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO usage_logs (key_id, endpoint, url, status_code, response_time_ms, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, endpoint, url, status_code, response_time_ms, time.time()),
        )
        await db.commit()

async def create_phone_verification(call_sid: str, key_id: str, business_phone: str, business_name: str, question: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO phone_verifications (call_sid, key_id, business_phone, business_name, question, status, created_at) VALUES (?, ?, ?, ?, ?, 'initiated', ?)",
            (call_sid, key_id, business_phone, business_name, question, time.time()),
        )
        await db.commit()

async def update_phone_verification(call_sid: str, status: str = None, transcription: str = None, recording_url: str = None, duration: int = None, answered_by: str = None):
    async with aiosqlite.connect(DB_PATH) as db:
        updates = ["completed_at = ?"]
        params = [time.time()]
        if status:
            updates.append("status = ?")
            params.append(status)
        if transcription:
            updates.append("transcription = ?")
            params.append(transcription)
        if recording_url:
            updates.append("recording_url = ?")
            params.append(recording_url)
        if duration is not None:
            updates.append("duration = ?")
            params.append(duration)
        if answered_by:
            updates.append("answered_by = ?")
            params.append(answered_by)
        params.append(call_sid)
        await db.execute(
            f"UPDATE phone_verifications SET {', '.join(updates)} WHERE call_sid = ?",
            params,
        )
        await db.commit()

async def get_phone_verification(call_sid: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT call_sid, key_id, business_phone, business_name, question, status, transcription, recording_url, duration, answered_by, created_at, completed_at FROM phone_verifications WHERE call_sid = ?",
            (call_sid,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "call_sid": row[0], "key_id": row[1], "business_phone": row[2],
                    "business_name": row[3], "question": row[4], "status": row[5],
                    "transcription": row[6], "recording_url": row[7], "duration": row[8],
                    "answered_by": row[9], "created_at": row[10], "completed_at": row[11],
                }
    return None

async def create_scam_report(phone: str, claimed_company: str = None, scam_score: int = None, reporter_ip: str = None, reporter_key_id: str = None, reasons: str = None):
    created_at = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scam_reports (phone, claimed_company, scam_score, reporter_ip, reporter_key_id, reasons, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (phone, claimed_company, scam_score, reporter_ip, reporter_key_id, reasons, created_at),
        )
        await db.commit()

async def get_scam_reports(phone: str, limit: int = 10):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT phone, claimed_company, scam_score, reasons, created_at FROM scam_reports WHERE phone = ? ORDER BY created_at DESC LIMIT ?",
            (phone, limit),
        ) as cursor:
            rows = await cursor.fetchall()
            return [{"phone": r[0], "claimed_company": r[1], "scam_score": r[2], "reasons": r[3], "reported_at": r[4]} for r in rows]

async def get_scam_report_count(phone: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM scam_reports WHERE phone = ?",
            (phone,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

TIER_LIMITS = {
    "free": {"daily": 50, "monthly": 150, "per_call": 0.00},
    "starter": {"daily": 67, "monthly": 2000, "per_call": 0.10},
    "pro": {"daily": 334, "monthly": 10000, "per_call": 0.50},
    "agency": {"daily": 1667, "monthly": 50000, "per_call": 0.25},
    "enterprise": {"daily": -1, "monthly": -1, "per_call": 0.05},
    # Pay-as-you-go tiers (one-time purchase credits)
    "payg_100": {"daily": 20, "monthly": 100, "per_call": 0.12},
    "payg_500": {"daily": 50, "monthly": 500, "per_call": 0.09},
    "payg_2000": {"daily": 200, "monthly": 2000, "per_call": 0.075},
}