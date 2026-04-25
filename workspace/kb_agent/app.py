"""
avp-agent-identity — Incident Knowledge Base Agent

This agent helps the security team find and summarize incidents.
It can read public incident fields (title, severity, status, created_at).
It cannot access sensitive fields (affected_customers, internal_notes,
remediation_details, postmortem_url) under any circumstances.

The key demo moment:
  A security engineer asks the KB agent to show affected customers for an incident.
  The agent calls IsAuthorized for read on incidents_sensitive.
  AVP returns DENY — the ceiling forbid policy applies to all agent principals.
  The engineer's own elevated session is irrelevant: the agent's Cedar identity
  has no permit for incidents_sensitive, and the ceiling policy means no developer
  can configure any agent with access to it.
  The query never runs. The denial is logged in CloudWatch.

Credential scoping:
  This process is launched by entrypoint.sh with SECURITY_ENGINEER_BWS_TOKEN
  stripped from its environment. It cannot see the engineer's credential even
  though both processes share the same container OS.
"""

import os
import json
import sys
import boto3
import psycopg2
import chainlit as cl
from anthropic import Anthropic

# bws_secrets.py is one level up in the workspace directory
sys.path.insert(0, "/app")
from bws_secrets import load_secrets

# ---------------------------------------------------------------------------
# Secrets and config
# ---------------------------------------------------------------------------
_secrets = load_secrets()

ANTHROPIC_API_KEY    = _secrets["ANTHROPIC_API_KEY"]
DB_INCIDENTS_PASSWORD = _secrets["DB_INCIDENTS_PASSWORD"]

AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

AGENT_PRINCIPAL_ID  = "kb-agent"

anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)

# Public fields the KB agent is permitted to see
PUBLIC_COLUMNS = ["id", "title", "severity", "status", "created_at"]


# ---------------------------------------------------------------------------
# AVP authorization helper
# ---------------------------------------------------------------------------
def is_authorized(action: str, resource: str) -> tuple[bool, str]:
    """
    Call AVP IsAuthorized for the kb-agent principal.
    Every call is logged to CloudWatch automatically.
    """
    response = avp_client.is_authorized(
        policyStoreId=AVP_POLICY_STORE_ID,
        principal={"entityType": "AgentIdentity::Agent", "entityId": AGENT_PRINCIPAL_ID},
        action={"actionType": "AgentIdentity::Action", "actionId": action},
        resource={"entityType": "AgentIdentity::DataStore", "entityId": resource},
        context={"contextMap": {"elevation_active": {"boolean": False}}},
    )
    decision = response["decision"]
    return decision == "ALLOW", decision


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    return psycopg2.connect(
        host="db-incidents",
        dbname="incidents",
        user="app",
        password=DB_INCIDENTS_PASSWORD,
    )


def list_incidents() -> list[dict]:
    allowed, decision = is_authorized("read", "incidents")
    if not allowed:
        raise PermissionError(f"AVP DENY: read incidents (decision: {decision})")
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


def get_incident(incident_id: int) -> dict | None:
    allowed, decision = is_authorized("read", "incidents")
    if not allowed:
        raise PermissionError(f"AVP DENY: read incidents (decision: {decision})")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, title, severity, status, created_at FROM incidents WHERE id = %s",
            (incident_id,),
        )
        row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "title": row[1], "severity": row[2], "status": row[3], "created_at": str(row[4])}


def attempt_sensitive(incident_id: int) -> str:
    """
    Called when the agent is asked to access sensitive incident fields.
    AVP will DENY this — the ceiling forbid policy applies to all agent principals.
    The engineer's own elevated session does not change this.
    """
    allowed, decision = is_authorized("read", "incidents_sensitive")
    if not allowed:
        raise PermissionError(
            f"AVP DENY: read incidents_sensitive (decision: {decision}). "
            f"This agent has no Cedar policy permitting access to sensitive incident fields. "
            f"The ceiling forbid policy applies to all agent principals regardless of configuration. "
            f"The denial has been logged to CloudWatch."
        )
    return "unreachable"


# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "list_incidents",
        "description": "List all incidents with public fields: title, severity, status, and date.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_incident",
        "description": "Get public details for a specific incident by ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "integer", "description": "The incident ID"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "get_sensitive_details",
        "description": (
            "Attempt to retrieve sensitive incident details: affected customers, internal notes, "
            "remediation details, or postmortem URL. "
            "NOTE: This agent does not have access to sensitive fields. AVP will deny this request."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "integer", "description": "The incident ID"},
            },
            "required": ["incident_id"],
        },
    },
]


def handle_tool_call(tool_name: str, tool_input: dict) -> str:
    try:
        if tool_name == "list_incidents":
            return json.dumps(list_incidents())
        elif tool_name == "get_incident":
            incident = get_incident(tool_input["incident_id"])
            if not incident:
                return json.dumps({"error": f"Incident {tool_input['incident_id']} not found."})
            return json.dumps(incident)
        elif tool_name == "get_sensitive_details":
            attempt_sensitive(tool_input["incident_id"])
            return json.dumps({"error": "unreachable"})
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
    except PermissionError as e:
        return json.dumps({"error": str(e), "avp_decision": "DENY"})


# ---------------------------------------------------------------------------
# Chainlit handlers
# ---------------------------------------------------------------------------
@cl.on_chat_start
async def on_chat_start():
    cl.user_session.set("messages", [])
    await cl.Message(
        content=(
            "Security Incident KB — I can help you find and summarize incidents. "
            "Ask me to list open incidents, check the status of a specific incident, "
            "or look up details by ID. "
            "For sensitive details (affected customers, internal notes, remediation), "
            "use the engineer portal at port 8001 with elevation."
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    messages = cl.user_session.get("messages")
    messages.append({"role": "user", "content": message.content})

    while True:
        response = anthropic_client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=(
                "You are a security incident knowledge base assistant. "
                "You can list incidents and retrieve public details: title, severity, status, and date. "
                "You have a get_sensitive_details tool but it will always return an AVP denial. "
                "You do not have access to affected customer lists, internal analyst notes, "
                "remediation details, or postmortem links. "
                "When sensitive access is denied, explain that those fields require engineer-level "
                "elevation via the engineer portal and are not accessible to this KB tool. "
                "Do not suggest that different instructions would change this."
            ),
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = handle_tool_call(block.name, block.input)
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     result,
                    })
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user",      "content": tool_results})
        else:
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")), ""
            )
            messages.append({"role": "assistant", "content": final_text})
            cl.user_session.set("messages", messages)
            await cl.Message(content=final_text).send()
            break
