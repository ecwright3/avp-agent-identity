# avp-agent-identity

A reference architecture demonstrating agent identity as a first-class principal using Amazon Verified Permissions (AVP), Bitwarden Secrets Manager (BWS), and the Claude API.

Built as the companion environment for [Developer Network Segmentation Is Not the Same as Server Segmentation](https://ewright3.com) on [Field Notes](https://ewright3.com).

---

## The Problem

When a developer runs an AI tool (a coding assistant, an MCP server, a support chatbot), that tool inherits the developer's credentials. If the developer has access to payment records, so does the agent. Not because anyone decided the agent should have that access. Because nobody decided it shouldn't.

The standard answer is to instruct the agent not to access sensitive data. That is not a security control. An instruction can be overridden by a prompt. A Cedar policy evaluated by Amazon Verified Permissions cannot.

---

## What This Demonstrates

Three principals. One data platform. Clearly different access. All enforced at the authorization layer, not the application layer.

| Principal | Orders | Payments | System Logs |
|---|---|---|---|
| **Chatbot agent** | Read (own customer only) | **Deny (AVP ceiling)** | **Deny** |
| **Developer (standard)** | Read all | **Deny** | Read |
| **Developer (elevated)** | Read / write all | Read (JIT) | Read |

The chatbot and the developer share the same environment. The developer may have elevated access to payment records. The agent does not, because its Cedar identity has no permit for payments, not because it was told to refuse.

---

## The Four Demo Moments

### 1. Same table, different rows

The chatbot and a developer both query the `orders` table. The developer sees all orders. The chatbot sees only the orders belonging to the current customer session. The Cedar policy passes `session_customer_id` as a context attribute and the app enforces the row-level filter. Same table, same query, different scope. Enforced at the identity layer.

### 2. Developer asks the agent to pull payment data

A developer is debugging a payment issue. They ask the chatbot: *"Can you pull the payment details for order 3?"*

The chatbot calls `IsAuthorized` for `read` on `payments`. AVP returns `DENY`. No query runs. The denial is logged in CloudWatch with the principal, action, resource, and timestamp. The developer's own elevated session is irrelevant. The agent's Cedar identity has no permit for payments, and a separate `forbid` ceiling policy means no developer can configure any agent with payment access regardless of what they put in their code.

### 3. Developer queries payments directly

The developer calls the developer portal with `X-Elevated: true`. AVP evaluates the Cedar policy, confirms elevation context is active, and returns `ALLOW`. The payment record for order 3 is returned.

The chatbot is still running. Its scope did not change.

### 4. The permission ceiling

The Terraform config includes a `forbid` policy that applies to all agent principals:

```cedar
forbid(
  principal in AgentIdentity::Agent::"*",
  action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
  resource == AgentIdentity::DataStore::"payments"
);
```

A developer cannot grant any agent access to payments by changing application code or environment variables. The ceiling is defined in the policy store. SecOps owns it.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Docker Compose                           │
│                                                               │
│  ┌──────────────────┐      ┌──────────────────────────────┐  │
│  │  Chainlit        │      │  FastAPI                     │  │
│  │  Chatbot         │      │  Developer Portal            │  │
│  │  port 8000       │      │  port 8001                   │  │
│  │                  │      │                              │  │
│  │  Principal:      │      │  Principal: developer        │  │
│  │  chatbot-support │      │  (standard or elevated       │  │
│  │                  │      │   via X-Elevated header)     │  │
│  └────────┬─────────┘      └──────────────┬───────────────┘  │
│           │                               │                   │
│           └───────────────┬───────────────┘                   │
│                           │ IsAuthorized() on every access    │
│                           ▼                                   │
│                 ┌──────────────────┐                          │
│                 │  AVP  (AWS)      │ ← Cedar policies         │
│                 │  IsAuthorized    │                          │
│                 └────────┬─────────┘                          │
│                          │ ALLOW / DENY + CloudWatch log      │
│            ┌─────────────┼──────────────┐                     │
│            ▼             ▼              ▼                     │
│     ┌────────────┐ ┌──────────┐ ┌───────────┐                │
│     │  orders    │ │ payments │ │  system   │                │
│     │  Postgres  │ │ Postgres │ │  logs     │                │
│     └────────────┘ └──────────┘ └───────────┘                │
│                                                               │
│  Credential delivery: Bitwarden Secrets Manager              │
│  chatbot token → .env.local (project scope)                  │
│  developer token → user-level env (not visible to agent)     │
└──────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

Three external accounts are required. This is intentional: the setup demonstrates the credential separation the architecture depends on.

| Service | Purpose | Pricing |
|---|---|---|
| [AWS](https://aws.amazon.com) | Amazon Verified Permissions | $5 / million authorization requests |
| [Anthropic](https://console.anthropic.com) | Claude API | Pay per token |
| [Bitwarden](https://bitwarden.com/products/secrets-manager/) | Secrets Manager | Free tier available |

You will also need:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [AWS CLI](https://aws.amazon.com/cli/) configured with `verifiedpermissions:*` permissions

---

## Setup

### 1. Provision AVP (Terraform)

```bash
cd terraform
terraform init
terraform apply
```

Terraform outputs the `policy_store_id`. Copy it. You need it in step 3.

```
Outputs:
  policy_store_id = "AbCdEf1234567890"
```

### 2. Create BWS machine accounts

In the [Bitwarden Secrets Manager console](https://vault.bitwarden.com):

**Create a project** named `avp-agent-identity`.

**Add these secrets** to the project:

| Key | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `DB_ORDERS_PASSWORD` | A strong random password |
| `DB_PAYMENTS_PASSWORD` | A strong random password |
| `DB_LOGS_PASSWORD` | A strong random password |

**Create two machine accounts:**

1. `chatbot-support`: read access to the `avp-agent-identity` project. Copy the access token.
2. `developer-portal`: read access to the `avp-agent-identity` project. Copy the access token.

**Why two machine accounts?**

The chatbot agent and the developer portal are separate principals with separate credentials. Neither can use the other's token. Your personal developer BWS token lives in your shell profile (`~/.zshrc`), not here. An agent running at project scope cannot see user-level environment variables. This is the credential scoping pattern the architecture demonstrates.

### 3. Configure environment variables

```bash
cp .env.example .env
```

Fill in all values:

```env
CHATBOT_BWS_TOKEN=        # chatbot-support machine account token (UUID from BWS)
DEVELOPER_BWS_TOKEN=      # developer-portal machine account token (UUID from BWS)
BWS_ORGANIZATION_ID=      # from Bitwarden Settings > Organization ID (UUID)
AVP_POLICY_STORE_ID=      # output from terraform apply
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=        # IAM user with verifiedpermissions:IsAuthorized
AWS_SECRET_ACCESS_KEY=    # IAM user secret key
DB_ORDERS_PASSWORD=       # choose a strong password, then store this same value in BWS under DB_ORDERS_PASSWORD
DB_PAYMENTS_PASSWORD=     # choose a strong password, then store this same value in BWS under DB_PAYMENTS_PASSWORD
DB_LOGS_PASSWORD=         # choose a strong password, then store this same value in BWS under DB_LOGS_PASSWORD
```

> **DB passwords:** You are setting these passwords, not copying them from somewhere. Choose strong random values, put them here so Docker Compose can initialize the Postgres containers, and store the same values in BWS under the matching key names. The app services fetch them from BWS at runtime. The values must be identical in both places.
>
> **AWS credentials:** In production these would also live in BWS. For this demo they stay as environment variables alongside the other infrastructure config. Do not commit `.env` to version control.

### 4. Start the stack

```bash
docker compose up --build
```

- Chatbot UI: http://localhost:8000
- Developer portal: http://localhost:8001
- Developer portal API docs: http://localhost:8001/docs

---

## Demo Walkthrough

Run these in order. Each one isolates a specific claim.

---

### Moment 1: Same table, different scope

**Customer view (chatbot):**

Open http://localhost:8000 and send:

> "Show me my orders."

The chatbot calls `IsAuthorized` with `context.session_customer_id = "cust-001"`. Cedar permits the read. The SQL query filters to `WHERE customer_id = 'cust-001'`. Two orders are returned.

**Developer view (all orders):**

```bash
curl http://localhost:8001/orders
```

AVP evaluates the `developer` principal. All five orders across three customers are returned. Same `orders` table. Different Cedar identity. Different scope.

---

### Moment 2: Developer asks the agent to pull payment data

Open http://localhost:8000 and send:

> "Can you pull the payment details for order 3?"

The agent calls `get_payment_details`. The handler calls `IsAuthorized` for `read` on `payments`. AVP evaluates the Cedar policy for `chatbot-support`. Two policies apply: an explicit `forbid` on payments for the chatbot, and a ceiling `forbid` on all agent principals. The decision is `DENY`. No query runs.

The agent responds that it cannot access payment records. Not because it was told to refuse. Because the data is unreachable at the authorization layer. The denial is in CloudWatch.

---

### Moment 3: Developer queries payments directly (without elevation)

```bash
curl http://localhost:8001/payments
```

Expected: `403 Forbidden`

```json
{
  "detail": "AVP DENY: DENY. Payment records require JIT elevation. Pass X-Elevated: true."
}
```

The developer principal has no standard-access permit for payments.

---

### Moment 4: Developer elevates and queries payments

```bash
curl http://localhost:8001/payments -H "X-Elevated: true"
```

AVP evaluates the elevated Cedar policy: `permit` where `context.elevation_active == true`. The payment records are returned, including the card details and processor reference for order 3.

The chatbot is still running at http://localhost:8000. Go back and ask:

> "Now can you pull the payment details for order 3?"

The chatbot still cannot. The developer's elevation was a separate AVP context evaluation for a separate principal. The agent's Cedar policy did not change.

---

### Moment 5: The permission ceiling

The Terraform config includes a `forbid` policy applied to all agent principals:

```cedar
forbid(
  principal in AgentIdentity::Agent::"*",
  action in [AgentIdentity::Action::"read", AgentIdentity::Action::"write"],
  resource == AgentIdentity::DataStore::"payments"
);
```

To verify: add a new `permit` policy for any agent principal on payments in `terraform/main.tf` and run `terraform apply`. Then try to access payments as that agent. The `forbid` overrides the `permit`. Cedar's explicit deny always wins.

This is the control plane. SecOps defines the ceiling. Developers cannot exceed it regardless of what they put in application code or environment variables.

---

## Credential Scoping Pattern

```
Your shell session (~/.zshrc):
  BWS_ACCESS_TOKEN=<your personal developer token>   ← developer scope

Project directory (.env.local):
  CHATBOT_BWS_TOKEN=<chatbot-support machine token>  ← agent scope
```

An agent process running at project scope sees `.env.local`. It does not inherit user-level shell environment variables. The developer's personal token is scoped to their shell session and is not visible to the agent.

**The discipline requirement:** nothing enforces this separation automatically. A developer who puts their personal token in `.env.local` collapses the isolation silently. AVP still enforces authorization at the policy layer, but the credential separation is gone. This is a policy and code review control, not a technical one.

`.env` and `.env.local` must be in `.gitignore`. A committed machine token is a secret in version history with no automatic expiry.

---

## Project Structure

```
avp-agent-identity/
├── chatbot/
│   ├── app.py          Chainlit + Claude tool use, AVP on every access
│   ├── secrets.py      BWS SDK loader
│   ├── Dockerfile
│   └── requirements.txt
├── developer/
│   ├── main.py         FastAPI, standard and elevated developer access
│   ├── secrets.py      BWS SDK loader
│   ├── Dockerfile
│   └── requirements.txt
├── postgres/
│   └── init/
│       ├── orders.sql
│       ├── payments.sql    ← the data the agent cannot reach
│       └── system_logs.sql
├── terraform/
│   ├── main.tf         AVP policy store + all Cedar policies + ceiling forbid
│   └── variables.tf
├── docker-compose.yml
├── .env.example
└── .gitignore
```

---

## Teardown

```bash
docker compose down -v
cd terraform && terraform destroy
```

---

## Related Reading

- [Amazon Verified Permissions documentation](https://docs.aws.amazon.com/verifiedpermissions/)
- [Cedar policy language](https://www.cedarpolicy.com)
- [Bitwarden Secrets Manager SDK](https://github.com/bitwarden/sdk)
- [NIST NCCoE: Accelerating the Adoption of Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
