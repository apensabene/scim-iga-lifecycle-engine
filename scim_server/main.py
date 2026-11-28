"""
RFC 7643 / 7644 SCIM 2.0 Provisioning Service Provider (FastAPI).

Supports Okta Joiner-Mover-Leaver (JML) lifecycle operations:
  - /scim/v2/ServiceProviderConfig, /Schemas, /ResourceTypes
  - /scim/v2/Users (GET list/filter, POST create, GET by id, PUT replace, PATCH op, DELETE)
  - /scim/v2/Groups (GET list, POST create, GET by id, PATCH members, DELETE)
  - /governance/audit-events (JML event ledger)

Security:
  - Constant-time Bearer token verification (SCIM_BEARER_TOKEN env var).
"""
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse

from .schemas import (
    SCIM_LIST_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimGroupCreate,
    ScimPatchRequest,
    ScimUserCreate,
    scim_error_payload,
)
from .storage import (
    _utc_now,
    format_group_resource,
    format_user_resource,
    get_conn,
    init_db,
    list_audit_events,
    log_jml_event,
)

SCIM_CONTENT_TYPE = "application/scim+json"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.environ.get("SCIM_BEARER_TOKEN"):
        raise RuntimeError("SCIM_BEARER_TOKEN environment variable must be set before starting.")
    init_db()
    yield


app = FastAPI(title="SCIM 2.0 Provisioning & IGA Service Provider", version="1.0.0", lifespan=lifespan)


def verify_bearer(authorization: Optional[str] = Header(default=None)) -> None:
    # Fail closed: this check must not depend on the lifespan startup guard having run.
    expected = os.environ.get("SCIM_BEARER_TOKEN", "").strip()
    if not expected:
        raise PermissionError("Invalid Bearer token")
    if not authorization or not authorization.startswith("Bearer "):
        raise PermissionError("Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise PermissionError("Missing Bearer token")
    if not secrets.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
        raise PermissionError("Invalid Bearer token")


@app.exception_handler(PermissionError)
async def auth_exception_handler(_: Request, exc: PermissionError):
    return JSONResponse(
        status_code=401,
        content=scim_error_payload(401, str(exc)),
        media_type=SCIM_CONTENT_TYPE,
    )


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ---------------- Discovery Endpoints ----------------
@app.get("/scim/v2/ServiceProviderConfig", dependencies=[Depends(verify_bearer)])
def service_provider_config():
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using the OAuth Bearer Token Standard",
                }
            ],
        },
        media_type=SCIM_CONTENT_TYPE,
    )


# ---------------- /Users Endpoints ----------------
@app.get("/scim/v2/Users", dependencies=[Depends(verify_bearer)])
def list_users(
    request: Request,
    filter: Optional[str] = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=500),
):
    base = _base_url(request)
    with get_conn() as conn:
        if filter and "userName eq" in filter:
            target = filter.split("userName eq", 1)[1].strip().strip('"').strip("'")
            rows = conn.execute("SELECT * FROM users WHERE user_name = ?", (target,)).fetchall()
        elif filter and "externalId eq" in filter:
            target = filter.split("externalId eq", 1)[1].strip().strip('"').strip("'")
            rows = conn.execute("SELECT * FROM users WHERE external_id = ?", (target,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()

    total = len(rows)
    sliced = rows[startIndex - 1 : startIndex - 1 + count]
    resources = [format_user_resource(r, base) for r in sliced]
    return JSONResponse(
        content={
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": total,
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        },
        media_type=SCIM_CONTENT_TYPE,
    )


@app.post("/scim/v2/Users", dependencies=[Depends(verify_bearer)])
def create_user(user: ScimUserCreate, request: Request):
    base = _base_url(request)
    uid = str(uuid.uuid4())
    now = _utc_now()
    payload = user.model_dump()
    if SCIM_USER_SCHEMA not in payload["schemas"]:
        payload["schemas"].insert(0, SCIM_USER_SCHEMA)

    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE user_name = ?", (user.userName,)).fetchone()
        if existing:
            return JSONResponse(
                status_code=409,
                content=scim_error_payload(409, f"User '{user.userName}' already exists.", "uniqueness"),
                media_type=SCIM_CONTENT_TYPE,
            )
        conn.execute(
            "INSERT INTO users (id, external_id, user_name, payload_json, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, user.externalId, user.userName, json.dumps(payload), int(user.active), now, now),
        )
        log_jml_event(conn, "JOINER_PROVISION", "User", uid, f"Provisioned SCIM user {user.userName}")
        row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    return JSONResponse(status_code=201, content=format_user_resource(row, base), media_type=SCIM_CONTENT_TYPE)


@app.get("/scim/v2/Users/{user_id}", dependencies=[Depends(verify_bearer)])
def get_user(user_id: str, request: Request):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return JSONResponse(status_code=404, content=scim_error_payload(404, "User not found"), media_type=SCIM_CONTENT_TYPE)
    return JSONResponse(content=format_user_resource(row, _base_url(request)), media_type=SCIM_CONTENT_TYPE)


@app.put("/scim/v2/Users/{user_id}", dependencies=[Depends(verify_bearer)])
def replace_user(user_id: str, user: ScimUserCreate, request: Request):
    now = _utc_now()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return JSONResponse(status_code=404, content=scim_error_payload(404, "User not found"), media_type=SCIM_CONTENT_TYPE)
        payload = user.model_dump()
        conn.execute(
            "UPDATE users SET external_id = ?, user_name = ?, payload_json = ?, active = ?, updated_at = ? WHERE id = ?",
            (user.externalId, user.userName, json.dumps(payload), int(user.active), now, user_id),
        )
        action = "MOVER_UPDATE" if user.active else "LEAVER_DEACTIVATE"
        log_jml_event(conn, action, "User", user_id, f"Updated user {user.userName} (active={user.active})")
        updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return JSONResponse(content=format_user_resource(updated, _base_url(request)), media_type=SCIM_CONTENT_TYPE)


@app.patch("/scim/v2/Users/{user_id}", dependencies=[Depends(verify_bearer)])
def patch_user(user_id: str, patch: ScimPatchRequest, request: Request):
    now = _utc_now()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return JSONResponse(status_code=404, content=scim_error_payload(404, "User not found"), media_type=SCIM_CONTENT_TYPE)

        payload = json.loads(row["payload_json"])
        active = bool(row["active"])

        for op in patch.Operations:
            verb = op.op.lower()
            if verb in ("replace", "add"):
                if op.path == "active" and isinstance(op.value, bool):
                    active = op.value
                    payload["active"] = active
                elif op.path is None and isinstance(op.value, dict):
                    if "active" in op.value:
                        active = bool(op.value["active"])
                    payload.update(op.value)
                elif op.path:
                    payload[op.path] = op.value

        conn.execute(
            "UPDATE users SET payload_json = ?, active = ?, updated_at = ? WHERE id = ?",
            (json.dumps(payload), int(active), now, user_id),
        )
        action = "LEAVER_SUSPEND" if not active else "MOVER_PATCH"
        log_jml_event(conn, action, "User", user_id, f"Patched {row['user_name']} (active={active})")
        updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    return JSONResponse(content=format_user_resource(updated, _base_url(request)), media_type=SCIM_CONTENT_TYPE)


@app.delete("/scim/v2/Users/{user_id}", dependencies=[Depends(verify_bearer)])
def delete_user(user_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT user_name FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return JSONResponse(status_code=404, content=scim_error_payload(404, "User not found"), media_type=SCIM_CONTENT_TYPE)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_jml_event(conn, "LEAVER_DELETE", "User", user_id, f"Hard-deleted SCIM user {row['user_name']}")
    return JSONResponse(status_code=204, content=None)


# ---------------- /Groups Endpoints ----------------
@app.get("/scim/v2/Groups", dependencies=[Depends(verify_bearer)])
def list_groups(request: Request):
    base = _base_url(request)
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM groups ORDER BY display_name ASC").fetchall()
    resources = [format_group_resource(r, base) for r in rows]
    return JSONResponse(
        content={
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": len(resources),
            "startIndex": 1,
            "itemsPerPage": len(resources),
            "Resources": resources,
        },
        media_type=SCIM_CONTENT_TYPE,
    )


@app.post("/scim/v2/Groups", dependencies=[Depends(verify_bearer)])
def create_group(group: ScimGroupCreate, request: Request):
    base = _base_url(request)
    gid = str(uuid.uuid4())
    now = _utc_now()
    members = [m.model_dump(by_alias=True, exclude_none=True) for m in group.members]
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM groups WHERE display_name = ?", (group.displayName,)).fetchone()
        if existing:
            return JSONResponse(
                status_code=409,
                content=scim_error_payload(409, f"Group '{group.displayName}' already exists.", "uniqueness"),
                media_type=SCIM_CONTENT_TYPE,
            )
        conn.execute(
            "INSERT INTO groups (id, external_id, display_name, members_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (gid, group.externalId, group.displayName, json.dumps(members), now, now),
        )
        log_jml_event(conn, "GROUP_CREATE", "Group", gid, f"Created entitlement group {group.displayName}")
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (gid,)).fetchone()
    return JSONResponse(status_code=201, content=format_group_resource(row, base), media_type=SCIM_CONTENT_TYPE)


@app.patch("/scim/v2/Groups/{group_id}", dependencies=[Depends(verify_bearer)])
def patch_group(group_id: str, patch: ScimPatchRequest, request: Request):
    now = _utc_now()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return JSONResponse(status_code=404, content=scim_error_payload(404, "Group not found"), media_type=SCIM_CONTENT_TYPE)

        members = json.loads(row["members_json"])
        for op in patch.Operations:
            verb = op.op.lower()
            if verb == "add" and op.path == "members" and isinstance(op.value, list):
                existing_ids = {m["value"] for m in members}
                for item in op.value:
                    if item.get("value") not in existing_ids:
                        members.append(item)
            elif verb == "remove" and op.path and op.path.startswith("members[value eq"):
                target_id = op.path.split("eq", 1)[1].rstrip("]").strip().strip('"').strip("'")
                members = [m for m in members if m.get("value") != target_id]
            elif verb == "replace" and op.path == "members" and isinstance(op.value, list):
                members = op.value

        conn.execute("UPDATE groups SET members_json = ?, updated_at = ? WHERE id = ?", (json.dumps(members), now, group_id))
        log_jml_event(conn, "ENTITLEMENT_SYNC", "Group", group_id, f"Updated members for {row['display_name']} (count={len(members)})")
        updated = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()

    return JSONResponse(content=format_group_resource(updated, _base_url(request)), media_type=SCIM_CONTENT_TYPE)


@app.get("/governance/audit-events", dependencies=[Depends(verify_bearer)])
def get_audit_events(limit: int = Query(default=50, ge=1, le=500)):
    return {"events": list_audit_events(limit)}