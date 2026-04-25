"""
avp-agent-identity — Developer Portal API

Demonstrates two developer personas against the same data stores:

  Standard (X-Elevated: false):
    - Read all orders
    - Read system logs
    - Payments: AVP DENY

  Elevated (X-Elevated: true):
    - Read/write all orders
    - Read payments
    - Read system logs

The key demo moment:
  A developer with elevated access asks their agent (chatbot) to pull
  payment data on their behalf. The agent's IsAuthorized call returns DENY
  because the agent's Cedar policy has no permit for payments — regardless
  of what the developer's own session can do.

  The developer can then call this API directly with X-Elevated: true
  and get the same payment data. The agent's scope did not change.
"""

import os
import boto3
import psycopg2
from fastapi import FastAPI, HTTPException, Header
from bws_secrets import load_secrets

_secrets = load_secrets()

DB_ORDERS_PASSWORD   = _secrets["DB_ORDERS_PASSWORD"]
DB_PAYMENTS_PASSWORD = _secrets["DB_PAYMENTS_PASSWORD"]
DB_LOGS_PASSWORD     = _secrets["DB_LOGS_PASSWORD"]

AVP_POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-1")

avp_client = boto3.client("verifiedpermissions", region_name=AWS_REGION)
app = FastAPI(title="Developer Portal", description=__doc__)


# ---------------------------------------------------------------------------
# AVP authorization helper
# ---------------------------------------------------------------------------
def is_authorized(principal_id: str, action: str, resource: str, context: dict = None) -> tuple[bool, str]:
    request = {
        "policyStoreId": AVP_POLICY_STORE_ID,
        "principal":     {"entityType": "AgentIdentity::User", "entityId": principal_id},
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


def get_db(host: str, password: str, dbname: str):
    return psycopg2.connect(host=host, dbname=dbname, user="app", password=password)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/orders", summary="List all orders (standard access)")
def list_orders(x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized("developer", "read", "orders", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
    conn = get_db("db-orders", DB_ORDERS_PASSWORD, "orders")
    with conn.cursor() as cur:
        cur.execute("SELECT id, customer_id, product, amount, status, created_at FROM orders ORDER BY id")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "customer_id": r[1], "product": r[2], "amount": str(r[3]), "status": r[4], "created_at": str(r[5])} for r in rows]


@app.put("/orders/{order_id}", summary="Update order status (elevated access required)")
def update_order(order_id: int, status: str, x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized("developer", "write", "orders", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"AVP DENY: {decision}. Write access to orders requires elevation. Pass X-Elevated: true."
        )
    conn = get_db("db-orders", DB_ORDERS_PASSWORD, "orders")
    with conn.cursor() as cur:
        cur.execute("UPDATE orders SET status = %s, updated_at = NOW() WHERE id = %s RETURNING id", (status, order_id))
        result = cur.fetchone()
    conn.commit()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
    return {"id": order_id, "status": status, "updated": True}


@app.get("/payments", summary="List payment records (elevated access required)")
def list_payments(x_elevated: bool = Header(default=False)):
    """
    This is the demo's key endpoint.

    A developer with elevation can call this and get payment records.
    The chatbot agent — running on the same developer machine — cannot.

    Try asking the chatbot: 'Can you pull the payment details for order 3?'
    The agent will attempt IsAuthorized for payments and receive DENY.
    Then call this endpoint with X-Elevated: true. The data is here.
    The agent's scope did not change when you elevated.
    """
    allowed, decision = is_authorized("developer", "read", "payments", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"AVP DENY: {decision}. Payment records require JIT elevation. Pass X-Elevated: true."
        )
    conn = get_db("db-payments", DB_PAYMENTS_PASSWORD, "payments")
    with conn.cursor() as cur:
        cur.execute("SELECT id, order_id, customer_id, card_last_four, card_brand, amount, status FROM payments ORDER BY id")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "order_id": r[1], "customer_id": r[2], "card_last_four": r[3], "card_brand": r[4], "amount": str(r[5]), "status": r[6]} for r in rows]


@app.get("/payments/{order_id}", summary="Get payment for a specific order (elevated access required)")
def get_payment(order_id: int, x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized("developer", "read", "payments", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"AVP DENY: {decision}. Payment records require JIT elevation. Pass X-Elevated: true."
        )
    conn = get_db("db-payments", DB_PAYMENTS_PASSWORD, "payments")
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, order_id, customer_id, card_last_four, card_brand, amount, status, processor_ref FROM payments WHERE order_id = %s",
            (order_id,)
        )
        row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"No payment record for order {order_id}")
    return {"id": row[0], "order_id": row[1], "customer_id": row[2], "card_last_four": row[3], "card_brand": row[4], "amount": str(row[5]), "status": row[6], "processor_ref": row[7]}


@app.get("/logs", summary="Read system logs (standard access)")
def list_logs(x_elevated: bool = Header(default=False)):
    allowed, decision = is_authorized("developer", "read", "system_logs", context={"elevation_active": x_elevated})
    if not allowed:
        raise HTTPException(status_code=403, detail=f"AVP DENY: {decision}")
    conn = get_db("db-logs", DB_LOGS_PASSWORD, "system_logs")
    with conn.cursor() as cur:
        cur.execute("SELECT id, level, service, message, metadata, created_at FROM system_logs ORDER BY created_at DESC")
        rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "level": r[1], "service": r[2], "message": r[3], "metadata": r[4], "created_at": str(r[5])} for r in rows]


@app.get("/health")
def health():
    return {"status": "ok"}
