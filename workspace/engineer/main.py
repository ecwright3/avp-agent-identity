"""
avp-agent-identity — Security Engineer Portal

Demonstrates two access levels against the same incidents table:

  Standard (X-Elevated: false):
    - Read public incident fields: id, title, severity, status, created_at
    - Same view the KB agent sees

  Elevated (X-Elevated: true):
    - Read full incident record including sensitive fields:
      affected_customers, internal_notes, remediation_details, postmortem_url

The key demo moment:
  A security engineer elevates to access sensitive incident fields.
  The KB agent is running concurrently in the same container.
  The agent's IsAuthorized call still returns DENY — its Cedar policy has no
  permit for incidents_sensitive, and the ceiling forbid cannot be overridden.
  The engineer's elevation was a separate AVP context evaluation for a separate
  principal. The agent's scope did not change.

Credential scoping:
  This process inherits SECURITY_ENGINEER_BWS_TOKEN from the container environment,
  simulating a developer token set in ~/.zshrc. The KB agent process does not have
  this token — entrypoint.sh strips it before launching the agent.
"""

import os
import sys
import boto3
import psycopg2
from fastapi import FastAPI, HTTPException, Header

sys.path.insert(0, "/app")
from bws_secrets import load_secrets

_secrets = load_secrets()

DB_INCIDENTS_PASSWORD = _secrets["DB_INCIDENTS_PASSWORD"]

AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)
app = FastAPI(title="Security Engineer Portal", description=__doc__)

PUBLIC_COLUMNS    = ["id", "title", "severity", "status", "created_at"]
SENSITIVE_COLUMNS = ["affected_customers", "internal_notes", "remediation_details", "postmortem_url"]


# ---------------------------------------------------------------------------
# AVP authorization helper
# ---------------------------------------------------------------------------
def is_authorized(action: str, resource: str, elevation_active: bool) -> tuple[bool, str]:
    response = avp_client.is_authorized(
        policyStoreId=AVP_POLICY_STORE_ID,
        principal={"entityType": "AgentIdentity::User", "entityId": "security-engineer"},
        action={"actionType": "AgentIdentity::Action", "actionId": action},
        resource={"entityType": "AgentIdentity::DataStore", "entityId": resource},
        context={"contextMap": {"elevation_active": {"boolean": elevation_active}}},
    )
    decision = response["decision"]
    return decision == "ALLOW", decision


def get_db():
    return psycopg2.connect(
        host="db-incidents",
        dbname="incidents",
        user="app",
        password=DB_INCIDENTS_PASSWORD,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/incidents", summary="List incidents — public fields (standard) or full record (elevated)")
def list_incidents(x_elevated: bool = Header(default=False)):
    """
    Without elevation: returns public fields only (same view as the KB agent).
    With X-Elevated: true: returns full record including sensitive fields.

    This is the core demo: same table, same endpoint, different scope based on
    principal identity and elevation state — enforced at the AVP layer.
    """
    if x_elevated:
        allowed, decision = is_authorized("read", "incidents_sensitive", elevation_active=True)
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail=f"AVP DENY: {decision}. Sensitive fields require elevation."
            )
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, severity, status, created_at, "
                "affected_customers, internal_notes, remediation_details, postmortem_url "
                "FROM incidents ORDER BY created_at DESC"
            )
            rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r[0], "title": r[1], "severity": r[2], "status": r[3],
                "created_at": str(r[4]), "affected_customers": r[5],
                "internal_notes": r[6], "remediation_details": r[7], "postmortem_url": r[8],
            }
            for r in rows
        ]
    else:
        allowed, decision = is_authorized("read", "incidents", elevation_active=False)
        if not allowed:
            raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, severity, status, created_at FROM incidents ORDER BY created_at DESC"
            )
            rows = cur.fetchall()
        conn.close()
        return [
            {"id": r[0], "title": r[1], "severity": r[2], "status": r[3], "created_at": str(r[4])}
            for r in rows
        ]


@app.get("/incidents/{incident_id}", summary="Get a single incident by ID")
def get_incident(incident_id: int, x_elevated: bool = Header(default=False)):
    if x_elevated:
        allowed, decision = is_authorized("read", "incidents_sensitive", elevation_active=True)
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail=f"AVP DENY: {decision}. Sensitive fields require elevation. Pass X-Elevated: true."
            )
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, severity, status, created_at, "
                "affected_customers, internal_notes, remediation_details, postmortem_url "
                "FROM incidents WHERE id = %s",
                (incident_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        return {
            "id": row[0], "title": row[1], "severity": row[2], "status": row[3],
            "created_at": str(row[4]), "affected_customers": row[5],
            "internal_notes": row[6], "remediation_details": row[7], "postmortem_url": row[8],
        }
    else:
        allowed, decision = is_authorized("read", "incidents", elevation_active=False)
        if not allowed:
            raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, severity, status, created_at FROM incidents WHERE id = %s",
                (incident_id,),
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
        return {
            "id": row[0], "title": row[1], "severity": row[2],
            "status": row[3], "created_at": str(row[4]),
        }


@app.get("/debug/env-scope", summary="Show credential scoping — demo use only")
def env_scope():
    """
    Reports whether SECURITY_ENGINEER_BWS_TOKEN is visible to this process.

    This process (engineer portal) should see it — it inherits the full
    container environment, simulating a developer token in ~/.zshrc.

    The KB agent process running in the same container should NOT see it —
    entrypoint.sh strips it before launching the agent.

    Compare this output with the KB agent's /debug/env-scope to prove
    process-level credential isolation on a shared OS.
    """
    token = os.environ.get("SECURITY_ENGINEER_BWS_TOKEN")
    return {
        "process": "security-engineer-portal",
        "SECURITY_ENGINEER_BWS_TOKEN_visible": token is not None,
        "note": (
            "PASS: engineer token is visible to this process (expected)."
            if token is not None else
            "FAIL: engineer token is not visible. Check container env configuration."
        ),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
