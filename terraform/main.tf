terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# AVP Policy Store
resource "aws_verifiedpermissions_policy_store" "main" {
  description = "avp-agent-identity demo policy store"

  validation_settings {
    mode = "STRICT"
  }
}

# ---------------------------------------------------------------------------
# Cedar schema
#
# Two principals: Agent (kb-agent) and User (security-engineer)
# Two resources: incidents (public fields) and incidents_sensitive (full record)
# The application applies the column filter based on the AVP decision.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_schema" "main" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id

  definition {
    value = <<-JSON
      {
        "AgentIdentity": {
          "entityTypes": {
            "Agent": {
              "shape": {
                "type": "Record",
                "attributes": {}
              }
            },
            "User": {
              "shape": {
                "type": "Record",
                "attributes": {}
              }
            },
            "DataStore": {
              "shape": {
                "type": "Record",
                "attributes": {}
              }
            }
          },
          "actions": {
            "read": {
              "appliesTo": {
                "principalTypes": ["Agent", "User"],
                "resourceTypes": ["DataStore"],
                "context": {
                  "type": "Record",
                  "attributes": {
                    "elevation_active": { "type": "Boolean", "required": true }
                  }
                }
              }
            }
          }
        }
      }
    JSON
  }
}

# ---------------------------------------------------------------------------
# KB agent policies
#
# The KB agent can read public incident fields (resource: incidents).
# It is explicitly forbidden from sensitive fields (resource: incidents_sensitive).
# The ceiling forbid at the bottom of this file enforces this regardless of
# any permit policy a developer might try to add.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "kb_agent_incidents_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id
  depends_on      = [aws_verifiedpermissions_schema.main]

  definition {
    static {
      description = "KB agent: read public incident fields (title, severity, status, created_at)"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::Agent::"kb-agent",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"incidents"
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "kb_agent_incidents_sensitive_deny" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id
  depends_on      = [aws_verifiedpermissions_schema.main]

  definition {
    static {
      description = "KB agent: explicitly forbidden from sensitive incident fields"
      statement   = <<-CEDAR
        forbid(
          principal == AgentIdentity::Agent::"kb-agent",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"incidents_sensitive"
        );
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# Permission ceiling
#
# No agent principal — regardless of how it is configured — can ever access
# incidents_sensitive. A permit policy added for any agent on incidents_sensitive
# will always be overridden by this forbid.
#
# This is the control plane claim: the security team defines the ceiling.
# Developers cannot grant any agent access above it.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "agent_ceiling_sensitive" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id
  depends_on      = [aws_verifiedpermissions_schema.main]

  definition {
    static {
      description = "Ceiling: no agent identity may access sensitive incident fields regardless of configuration"
      statement   = <<-CEDAR
        forbid(
          principal is AgentIdentity::Agent,
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"incidents_sensitive"
        );
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# Security engineer policies
#
# Standard: read public incident fields.
# Elevated (JIT): read sensitive fields. Elevation is a context attribute
# passed by the app server — the client cannot set it.
# ---------------------------------------------------------------------------

resource "aws_verifiedpermissions_policy" "engineer_incidents_read" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id
  depends_on      = [aws_verifiedpermissions_schema.main]

  definition {
    static {
      description = "Security engineer (standard): read public incident fields"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"security-engineer",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"incidents"
        );
      CEDAR
    }
  }
}

resource "aws_verifiedpermissions_policy" "engineer_incidents_sensitive_elevated" {
  policy_store_id = aws_verifiedpermissions_policy_store.main.id
  depends_on      = [aws_verifiedpermissions_schema.main]

  definition {
    static {
      description = "Security engineer (elevated): read full incident record including sensitive fields — JIT only"
      statement   = <<-CEDAR
        permit(
          principal == AgentIdentity::User::"security-engineer",
          action == AgentIdentity::Action::"read",
          resource == AgentIdentity::DataStore::"incidents_sensitive"
        )
        when { context.elevation_active == true };
      CEDAR
    }
  }
}

# ---------------------------------------------------------------------------
# IAM user for AVP authorization calls
#
# Least-privilege: only verifiedpermissions:IsAuthorized on this policy store.
# ---------------------------------------------------------------------------

resource "aws_iam_user" "avp_agent" {
  name = "avp-agent-identity-demo"
}

resource "aws_iam_policy" "avp_is_authorized" {
  name        = "avp-agent-identity-IsAuthorized"
  description = "Allow IsAuthorized calls against the avp-agent-identity policy store only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "verifiedpermissions:IsAuthorized"
        Resource = "arn:aws:verifiedpermissions::${data.aws_caller_identity.current.account_id}:policy-store/${aws_verifiedpermissions_policy_store.main.id}"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "avp_agent" {
  user       = aws_iam_user.avp_agent.name
  policy_arn = aws_iam_policy.avp_is_authorized.arn
}

resource "aws_iam_access_key" "avp_agent" {
  user = aws_iam_user.avp_agent.name
}

data "aws_caller_identity" "current" {}

output "policy_store_id" {
  description = "Copy this value into AVP_POLICY_STORE_ID in your .env file"
  value       = aws_verifiedpermissions_policy_store.main.id
}

output "aws_access_key_id" {
  description = "Copy into BWS as AWS_ACCESS_KEY_ID"
  value       = aws_iam_access_key.avp_agent.id
}

output "aws_secret_access_key" {
  description = "Copy into BWS as AWS_SECRET_ACCESS_KEY"
  value       = aws_iam_access_key.avp_agent.secret
  sensitive   = true
}
