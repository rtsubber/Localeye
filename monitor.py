#!/usr/bin/env python3
"""Local-Eye API monitoring: abuse alerts + weekly reports."""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB_PATH = Path("/home/ron/.openclaw/workspace/agent-check/agent_check.db")
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "")  # Set via .env
TZ_OFFSET = -5  # CT (CDT = -5, CST = -6)

def get_signups(hours=24):
    """Get signups from the last N hours."""
    cutoff = time.time() - (hours * 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT key_id, email, tier, created_at, registration_ip FROM api_keys WHERE created_at > ? ORDER BY created_at DESC",
        (cutoff,),
    )
    rows = c.fetchall()
    conn.close()
    return rows

def get_suspicious_ips(hours=168):
    """Find IPs with 3+ registrations in the last N hours."""
    cutoff = time.time() - (hours * 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT registration_ip, COUNT(*) as cnt FROM api_keys WHERE created_at > ? AND registration_ip IS NOT NULL GROUP BY registration_ip HAVING cnt >= 3 ORDER BY cnt DESC",
        (cutoff,),
    )
    rows = c.fetchall()
    conn.close()
    return rows

def get_usage_stats(hours=24):
    """Get usage stats for the period."""
    cutoff = time.time() - (hours * 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM usage_logs WHERE created_at > ?", (cutoff,))
    total_calls = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT key_id) FROM usage_logs WHERE created_at > ?", (cutoff,))
    active_keys = c.fetchone()[0]
    c.execute(
        "SELECT endpoint, COUNT(*) FROM usage_logs WHERE created_at > ? GROUP BY endpoint ORDER BY COUNT(*) DESC",
        (cutoff,),
    )
    by_endpoint = c.fetchall()
    conn.close()
    return total_calls, active_keys, by_endpoint

def format_abuse_alert():
    """Format an abuse alert message."""
    signups = get_signups(hours=12)
    suspicious = get_suspicious_ips(hours=168)
    
    if not suspicious:
        return None  # No abuse to report
    
    msg = "⚠️ **Local-Eye: Abuse Alert**\n\n"
    msg += "**Suspicious IPs (3+ signups):**\n"
    for ip, count in suspicious:
        msg += f"  • `{ip}` — {count} registrations\n"
    
    msg += f"\n**Last 12h signups:** {len(signups)}\n"
    
    # Show signups from suspicious IPs
    sus_ips = {ip for ip, _ in suspicious}
    flagged = [s for s in signups if s[4] in sus_ips]
    if flagged:
        msg += "\n**Flagged signups:**\n"
        for s in flagged:
            ts = datetime.fromtimestamp(s[3], tz=timezone(timedelta(hours=TZ_OFFSET))).strftime('%m/%d %I:%M %p')
            msg += f"  • {s[1]} ({s[2]}) — IP: `{s[4]}` — {ts}\n"
    
    return msg

def format_weekly_report():
    """Format a weekly summary report."""
    signups = get_signups(hours=168)
    suspicious = get_suspicious_ips(hours=168)
    total_calls, active_keys, by_endpoint = get_usage_stats(hours=168)
    
    now_ct = datetime.now(timezone(timedelta(hours=TZ_OFFSET)))
    
    msg = "📊 **Local-Eye: Weekly Report**\n"
    msg += f"Week ending {now_ct.strftime('%b %d, %Y')}\n\n"
    
    # Signups
    msg += f"**New Signups:** {len(signups)}\n"
    tiers = {}
    for s in signups:
        tier = s[2] or "free"
        tiers[tier] = tiers.get(tier, 0) + 1
    for tier, count in sorted(tiers.items()):
        msg += f"  • {tier}: {count}\n"
    
    # Usage
    msg += f"\n**API Calls This Week:** {total_calls}\n"
    msg += f"**Active Keys:** {active_keys}\n"
    if by_endpoint:
        msg += "\n**By Endpoint:**\n"
        for endpoint, count in by_endpoint:
            msg += f"  • {endpoint}: {count}\n"
    
    # Suspicious activity
    if suspicious:
        msg += f"\n⚠️ **Suspicious IPs:** {len(suspicious)}\n"
        for ip, count in suspicious:
            msg += f"  • `{ip}` — {count} registrations\n"
    else:
        msg += "\n✅ No suspicious activity detected\n"
    
    # Top users
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT u.key_id, k.email, k.tier, COUNT(*) as calls FROM usage_logs u LEFT JOIN api_keys k ON u.key_id = k.key_id WHERE u.created_at > ? GROUP BY u.key_id ORDER BY calls DESC LIMIT 5",
        (time.time() - 168 * 3600,),
    )
    top_users = c.fetchall()
    conn.close()
    
    if top_users:
        msg += "\n**Top Users This Week:**\n"
        for row in top_users:
            email = row[1] or "unknown"
            tier = row[2] or "free"
            calls = row[3]
            msg += f"  • {email} ({tier}) — {calls} calls\n"
    
    return msg

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "weekly":
        print(format_weekly_report())
    else:
        alert = format_abuse_alert()
        if alert:
            print(alert)
        else:
            print("✅ No abuse detected — all clear")