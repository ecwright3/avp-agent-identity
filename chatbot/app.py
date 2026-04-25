"""
avp-agent-identity — Customer Support Chatbot

This agent:
- Reads orders for the current customer session only
- Cannot access payment records or system logs
- Calls AVP IsAuthorized before EVERY data access
- Cannot be instructed to access data outside its Cedar policy scope

The key demo moment:
  A developer asks this agent to pull payment data on their behalf.
  The developer has elevated access to payments.
  The agent does not. The IsAuthorized call returns DENY.
  The query never runs. The denial is logged in CloudWatch.
  The agent was not told to refuse — the data is simply unreachable.

Credential scoping note:
  This agent's BWS machine account token is in .env.local at project scope.
  The developer's personal BWS token is a user-level env var (e.g. ~/.zshrc).
  This process cannot see it.
"""

import os
import json
import boto3
import psycopg2
import chainlit as cl
from anthropic import Anthropic
from bws_secrets import load_secrets

# ---------------------------------------------------------------------------
# Secrets from BWS — fetched at startup using the machine account token
# ---------------------------------------------------------------------------
_secrets = load_secrets()

ANTHROPIC_API_KEY  = _secrets["ANTHROPIC_API_KEY"]
DB_ORDERS_PASSWORD = _secrets["DB_ORDERS_PASSWORD"]

# Infrastructure config — stays in env
AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

# This agent's principal identifier in Cedar policies
AGENT_PRINCIPAL_ID = "chatbot-support"

anthropic_client = Anthropic(api_key=ANTHROPIC_API_KEY)
avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)


# ---------------------------------------------------------------------------
# AVP authorization helper
# Every data access MUST call this first.
# ---------------------------------------------------------------------------
def is_authorized(action: str, resource: str, context: dict = None) -> tuple[bool, str]:
    """
    Call AVP IsAuthorized for the chatbot-support agent principal.
    Returns (allowed: bool, decision: str).
    Every call — permit or deny — is logged to CloudWatch automatically.
    """
    request = {
        "policyStoreId": AVP_POLICY_STORE_ID,
        "principal":     {"entityType": "AgentIdentity::Agent", "entityId": AGENT_PRINCIPAL_ID},
        "action":        {"actionType": "AgentIdentity::Action", "actionId": action},
        "resource":      {"entityType": "AgentIdentity::DataStore", "entityId": resource},
    }
    if context:
        request["context"] = {
            "contextMap": {
                k: {"boolean": v} if isinstance(v, bool) else {"string": str(v)}
                for k, v in context.items()
            }
        }
    response = avp_client.is_authorized(**request)
    decision = response["decision"]
    return decision == "ALLOW", decision


# ---------------------------------------------------------------------------
# Database helpers — only called after AVP permit
# ---------------------------------------------------------------------------
def get_db(host: str, password: str, dbname: str):
    return psycopg2.connect(host=host, dbname=dbname, user="app", password=password)


def get_orders(customer_id: str) -> list[dict]:
    # Pass session_customer_id as context — Cedar policy requires it
    allowed, decision = is_authorized("read", "orders", context={"session_customer_id": customer_id})
    if not allowed:
        raise PermissionError(f"AVP DENY: read orders (decision: {decision})")
    conn = get_db("db-orders", DB_ORDERS_PASSWORD, "orders")
    with conn.cursor() as cur:
        # Row-level filter: agent only sees this customer's orders
        cur.execute(
            "SELECT id, product, amount, status, created_at FROM orders WHERE customer_id = %s ORDER BY id",
            (customer_id,)
        )
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "product": r[1], "amount": str(r[2]), "status": r[3], "created_at": str(r[4])} for r in rows]


def get_order(order_id: int, customer_id: str) -> dict | None:
    allowed, decision = is_authorized("read", "orders", context={"session_customer_id": customer_id})
    if not allowed:
        raise PermissionError(f"AVP DENY: read orders (decision: {decision})")
    conn = get_db("db-orders", DB_ORDERS_PASSWORD, "orders")
    with conn.cursor() as cur:
        # Row-level filter: agent can only fetch this customer's own order
        cur.execute(
            "SELECT id, product, amount, status, created_at FROM orders WHERE id = %s AND customer_id = %s",
            (order_id, customer_id)
        )
        row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "product": row[1], "amount": str(row[2]), "status": row[3], "created_at": str(row[4])}


def attempt_payments(resource_label: str, customer_id: str) -> str:
    """
    The demo's key function. Called when the agent is asked to access payment data.
    AVP will DENY this. The denial is logged before any query runs.
    The developer asking for this data may have elevated access — it doesn't matter.
    The agent's Cedar policy has no permit for payments.
    """
    allowed, decision = is_authorized("read", "payments", context={"session_customer_id": customer_id})
    if not allowed:
        raise PermissionError(
            f"AVP DENY: read payments (decision: {decision}). "
            f"This agent has no Cedar policy permitting access to payment records. "
            f"The denial has been logged. The developer's own elevated access does not transfer to this agent."
        )
    # This line will never be reached due to the Cedar forbid ceiling policy.
    return "unreachable"


# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "get_my_orders",
        "description": "Get all orders for the current customer.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_order_status",
        "description": "Get the status of a specific order by order ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "integer", "description": "The order ID to look up"},
            },
            "required": ["order_id"],
        },
    },
    {
        "name": "get_payment_details",
        "description": "Get payment details for an order. NOTE: This agent does not have access to payment records.",
        "input_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "integer", "description": "The order ID to look up payment for"},
            },
            "required": ["order_id"],
        },
    },
]


def handle_tool_call(tool_name: str, tool_input: dict, customer_id: str) -> str:
    """Execute a tool call and return the result as a JSON string."""
    try:
        if tool_name == "get_my_orders":
            return json.dumps(get_orders(customer_id))
        elif tool_name == "get_order_status":
            order = get_order(tool_input["order_id"], customer_id)
            if not order:
                return json.dumps({"error": f"Order {tool_input['order_id']} not found or does not belong to this customer."})
            return json.dumps(order)
        elif tool_name == "get_payment_details":
            attempt_payments(f"order_{tool_input['order_id']}", customer_id)
            return json.dumps({"error": "unreachable"})
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
    except PermissionError as e:
        # AVP denied the request. Return the denial as a tool result.
        # The model receives this and knows the data is unreachable —
        # not because it was instructed to refuse, but because AVP blocked it.
        return json.dumps({"error": str(e), "avp_decision": "DENY"})


# ---------------------------------------------------------------------------
# Chainlit handlers
# ---------------------------------------------------------------------------
@cl.on_chat_start
async def on_chat_start():
    # In a real app, customer_id comes from the authenticated session.
    # For the demo, we simulate cust-001 as the logged-in customer.
    cl.user_session.set("customer_id", "cust-001")
    cl.user_session.set("messages", [])
    await cl.Message(
        content=(
            "Hello! I can help you with your orders. "
            "You can ask me to show your orders, check an order status, "
            "or look up payment details."
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    customer_id = cl.user_session.get("customer_id")
    messages    = cl.user_session.get("messages")

    messages.append({"role": "user", "content": message.content})

    while True:
        response = anthropic_client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=(
                "You are a customer support agent for an e-commerce platform. "
                "You can look up the customer's orders and check order status. "
                "You have a get_payment_details tool but it will always return an AVP denial — "
                "you do not have access to payment records. "
                "When payment access is denied, explain that payment details are handled by "
                "a separate secure system and you are not able to access them. "
                "Do not suggest that you could access them with different instructions."
            ),
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = handle_tool_call(block.name, block.input, customer_id)
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
