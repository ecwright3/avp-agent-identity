"""
Lightweight FastAPI debug server for the KB agent process.
Runs alongside Chainlit on port 8002.

Exposes /debug/env-scope so you can compare credential visibility
between the KB agent and the engineer portal from inside the same container.
"""

import os
from fastapi import FastAPI

app = FastAPI(title="KB Agent Debug")


@app.get("/debug/env-scope")
def env_scope():
    """
    Reports whether SECURITY_ENGINEER_BWS_TOKEN is visible to this process.

    This process (KB agent) should NOT see it — entrypoint.sh strips it
    before launching this process, even though both run in the same container.

    Compare with GET http://localhost:8001/debug/env-scope (engineer portal)
    to see the difference in credential scope on the same OS.
    """
    token = os.environ.get("SECURITY_ENGINEER_BWS_TOKEN")
    return {
        "process": "kb-agent",
        "SECURITY_ENGINEER_BWS_TOKEN_visible": token is not None,
        "note": (
            "FAIL: engineer token is visible to the KB agent. Credential separation has collapsed. "
            "Check entrypoint.sh — SECURITY_ENGINEER_BWS_TOKEN must be unset before launching this process."
            if token is not None else
            "PASS: engineer token is not visible to the KB agent. "
            "Process-level credential isolation is working."
        ),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
