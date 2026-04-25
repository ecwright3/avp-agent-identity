-- incidents — single table, two access levels enforced by AVP
--
-- Public fields:  id, title, severity, status, created_at
-- Sensitive fields: affected_customers, internal_notes, remediation_details, postmortem_url
--
-- The KB agent is permitted to read public fields only (resource: incidents).
-- The security engineer is permitted to read all fields when elevated (resource: incidents_sensitive).
-- The application applies the column filter based on the AVP decision.

CREATE TABLE incidents (
    id                   SERIAL PRIMARY KEY,
    title                VARCHAR(200) NOT NULL,
    severity             VARCHAR(20)  NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    status               VARCHAR(30)  NOT NULL CHECK (status IN ('open','investigating','contained','resolved')),
    created_at           TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMP,
    -- sensitive fields: never returned without AVP permit for incidents_sensitive
    affected_customers   TEXT,
    internal_notes       TEXT,
    remediation_details  TEXT,
    postmortem_url       TEXT
);

INSERT INTO incidents (title, severity, status, created_at, affected_customers, internal_notes, remediation_details, postmortem_url) VALUES
(
    'Credential stuffing spike — auth service',
    'high',
    'investigating',
    NOW() - INTERVAL '3 hours',
    '~1,200 accounts attempted; 47 confirmed compromised (customer IDs: 10041, 10089, 10204, 10388, 10512)',
    'Attacker IP ranges cluster in AS14061 (DigitalOcean). Rate limiting triggered at 09:14 UTC but threshold was too high. MFA bypass attempted on 12 accounts via SIM swap — 2 succeeded.',
    'Blocked AS14061 CIDR blocks at WAF layer. Reset credentials for 47 affected accounts. Lowering rate limit threshold from 100 to 20 req/min. MFA recovery path under review.',
    'https://internal.wiki/postmortems/2026-04-25-credential-stuffing'
),
(
    'S3 bucket misconfiguration — data exports',
    'critical',
    'contained',
    NOW() - INTERVAL '2 days',
    'Export bucket exposed: ~8,400 customer records including PII (name, email, last-four). Customer IDs 9000–17400 range. Regulatory notification required in 22 hours.',
    'Bucket policy was modified during infrastructure migration on 2026-04-22 by automated Terraform run. Public access block was inadvertently disabled. Discovered via external researcher disclosure (responsible disclosure, no evidence of exfiltration).',
    'Bucket re-locked. Public access block re-enabled and SCO enforced. CloudTrail alert added for public ACL changes. Legal and compliance notified. Breach notification draft in progress.',
    'https://internal.wiki/postmortems/2026-04-23-s3-exposure'
),
(
    'Anomalous API access — payments service',
    'medium',
    'resolved',
    NOW() - INTERVAL '5 days',
    'No customer data confirmed exfiltrated. 3 internal service accounts queried outside normal hours.',
    'Automated job misconfiguration caused off-hours queries. No malicious actor identified. Service account tokens rotated as precaution.',
    'Cron schedule corrected. Added after-hours anomaly alert for payment service account activity.',
    'https://internal.wiki/postmortems/2026-04-20-api-anomaly'
),
(
    'Phishing campaign targeting engineering org',
    'high',
    'open',
    NOW() - INTERVAL '1 hour',
    '4 engineers clicked link. 1 credential harvested (engineer ID: E-0412). SSO session invalidated.',
    'Campaign impersonating internal IT helpdesk. Lure: "Your VPN certificate is expiring." Payload collects SSO credentials via reverse proxy phishing kit. Domain registered 6 hours before campaign launched.',
    'Affected SSO session invalidated. Password reset forced for E-0412. IOC (domain, IP) shared with email provider. All-hands phishing alert sent. Reviewing MFA enrollment for engineering org.',
    'https://internal.wiki/incidents/2026-04-25-phishing'
),
(
    'Dependency confusion — internal package registry',
    'low',
    'resolved',
    NOW() - INTERVAL '12 days',
    'No production systems affected. 2 developer workstations executed test package.',
    'Researcher published a proof-of-concept package to the public registry matching an internal package name. Package phoned home but contained no malicious payload. Workstations belonged to junior engineers running experimental builds.',
    'Internal packages now namespaced with private scope prefix. Registry priority order locked. Developer workstation EDR rules updated.',
    'https://internal.wiki/postmortems/2026-04-13-dep-confusion'
);
