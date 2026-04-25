#!/bin/bash
set -e

# =============================================================================
# Workspace entrypoint — simulates a shared developer machine
#
# Both the KB agent and the security engineer portal run as sibling processes
# inside this single container. This is the key demo environment: same OS,
# same filesystem, same network, different credential scope per process.
#
# Credential scoping:
#   SECURITY_ENGINEER_BWS_TOKEN is set in the container environment (simulating
#   a developer token exported in ~/.zshrc). The engineer portal inherits it.
#   The KB agent is launched with it stripped — the agent process cannot see
#   the engineer's token even though they share the same OS.
#
# The discipline requirement: nothing enforces this automatically. A developer
# who removes the `env -u` call collapses the isolation silently. This is a
# code review control, not a technical guarantee.
# =============================================================================

echo "[entrypoint] Starting workspace — two processes, one container"

# ---------------------------------------------------------------------------
# Process 1: KB agent
# Strip SECURITY_ENGINEER_BWS_TOKEN before launching so the agent process
# cannot see the engineer's credential. Set BWS_ACCESS_TOKEN to the KB agent
# machine account token for BWS secret injection.
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting KB agent (port 8000) with scoped credentials"
env -u SECURITY_ENGINEER_BWS_TOKEN \
    BWS_ACCESS_TOKEN="$KB_BWS_TOKEN" \
    chainlit run /app/kb_agent/app.py --host 0.0.0.0 --port 8000 &

KB_PID=$!
echo "[entrypoint] KB agent PID: $KB_PID"

# Also start the KB agent debug server on port 8002
# Inherits the same environment as the KB agent (no engineer token)
env -u SECURITY_ENGINEER_BWS_TOKEN \
    uvicorn kb_agent.debug:app --host 0.0.0.0 --port 8002 &

# ---------------------------------------------------------------------------
# Process 2: Security engineer portal
# Inherits full container env including SECURITY_ENGINEER_BWS_TOKEN.
# Set BWS_ACCESS_TOKEN to the engineer machine account token.
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting security engineer portal (port 8001) with full credentials"
BWS_ACCESS_TOKEN="$SECURITY_ENGINEER_BWS_TOKEN" \
    uvicorn engineer.main:app --host 0.0.0.0 --port 8001 &

ENGINEER_PID=$!
echo "[entrypoint] Engineer portal PID: $ENGINEER_PID"

echo "[entrypoint] Both processes running. KB agent: 8000, Engineer portal: 8001, KB debug: 8002"

# Wait for either process to exit — if one dies, surface the failure
wait -n
echo "[entrypoint] A process exited. Shutting down."
kill $KB_PID $ENGINEER_PID 2>/dev/null || true
