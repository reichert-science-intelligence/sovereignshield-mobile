"""
Platform Hub — Supabase client for platform_sessions and cross_app_findings.
Shared by AuditShield, StarGuard, and SovereignShield integrations.
Uses PLATFORM_SUPABASE_URL (platform hub project) when set, else SUPABASE_URL.
Uses PLATFORM_SUPABASE_ANON_KEY when set, else SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY.
Schema: platform_sessions (app_name, created_at), cross_app_findings (status DEFAULT 'open').
"""
from __future__ import annotations

import os
from typing import Any

_client: Any = None


def _get_client():
    """Lazy Supabase client. Returns None if not configured."""
    global _client
    if _client is not None:
        return _client
    try:
        from supabase import create_client
        url = os.environ.get("PLATFORM_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
        key = (
            os.environ.get("PLATFORM_SUPABASE_ANON_KEY")
            or os.environ.get("SUPABASE_ANON_KEY")
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY")
        )
        if url and key:
            _client = create_client(url, key)
            return _client
    except Exception:
        pass
    return None


def insert_platform_session(app_name: str, session_id: str | None = None, **kwargs) -> str | None:
    """Insert a row into platform_sessions. Returns UUID string or None."""
    client = _get_client()
    if not client:
        return None
    try:
        row: dict[str, Any] = {
            "app_name": app_name,
            "session_id": str(session_id) if session_id else None,
        }
        row.update(kwargs)
        r = client.table("platform_sessions").insert(row).execute()
        if r.data and len(r.data) > 0:
            return str(r.data[0].get("id", ""))
    except Exception:
        pass
    return None


def insert_cross_app_finding(
    source_app: str,
    finding_type: str,
    title: str,
    description: str | None = None,
    severity: str = "medium",
    session_id: str | None = None,
    **kwargs,
) -> str | None:
    """Insert a row into cross_app_findings. Returns UUID string or None."""
    client = _get_client()
    if not client:
        return None
    try:
        row: dict[str, Any] = {
            "source_app": source_app,
            "finding_type": finding_type,
            "title": title,
            "description": description or "",
            "severity": severity,
            "status": "open",
        }
        if session_id is not None:
            row["session_id"] = session_id
        row.update(kwargs)
        r = client.table("cross_app_findings").insert(row).execute()
        if r.data and len(r.data) > 0:
            return str(r.data[0].get("id", ""))
    except Exception:
        pass
    return None
