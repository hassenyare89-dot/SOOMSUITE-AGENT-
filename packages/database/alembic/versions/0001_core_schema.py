"""Core multi-tenant schema: identity, CRM, scheduling, conversations, knowledge, SOC, approvals,
audit, agent runs.

Revision ID: 0001_core_schema
Revises:
Create Date: 2026-09-24
"""

from alembic import op

from platform_core.db.sqlscript import execute_script

revision = "0001_core_schema"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "users", "user_roles", "integrations", "widget_sites", "companies", "contacts",
    "opportunities", "crm_activities", "crm_notes", "crm_tasks", "appointment_types",
    "appointments", "conversations", "messages", "knowledge_documents", "knowledge_chunks",
    "notifications", "assets", "asset_verifications", "security_events", "incidents",
    "incident_events", "approval_requests", "scan_jobs", "findings", "malware_results",
    "waf_actions", "agent_runs", "tool_calls", "audit_logs",
]

SCHEMA = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Helper returning the tenant bound to the current transaction (NULL when unset).
CREATE FUNCTION app_current_tenant() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS
$$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE FUNCTION app_touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN NEW.updated_at := now(); RETURN NEW; END $$;

-- ------------------------------------------------------------------ identity & tenancy
CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL CONSTRAINT uq_tenants_slug UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','offboarding')),
  timezone text NOT NULL DEFAULT 'UTC',
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  external_subject text NOT NULL,
  email_ciphertext text,
  email_hash varchar(64),
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','invited')),
  mfa_enforced boolean NOT NULL DEFAULT true,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT uq_users_tenant_subject UNIQUE (tenant_id, external_subject)
);
CREATE INDEX ix_users_tenant_email_hash ON users (tenant_id, email_hash);

CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CONSTRAINT uq_roles_name UNIQUE,
  description text NOT NULL DEFAULT '',
  is_system boolean NOT NULL DEFAULT true
);

CREATE TABLE permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CONSTRAINT uq_permissions_name UNIQUE,
  description text NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_by uuid,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  kind text NOT NULL CHECK (kind ~ '^[a-z0-9_.]+$'),
  name text NOT NULL,
  external_key text,
  secret_ref text CHECK (secret_ref IS NULL OR secret_ref ~ '^(env|file|vault|aws-sm)://'),
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- Routing keys are globally unique per kind (resolved before tenant context exists).
CREATE UNIQUE INDEX uq_integrations_kind_external_key ON integrations (kind, external_key)
  WHERE external_key IS NOT NULL;
CREATE INDEX ix_integrations_tenant_kind ON integrations (tenant_id, kind);

CREATE TABLE widget_sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  public_key text NOT NULL CONSTRAINT uq_widget_sites_public_key UNIQUE,
  name text NOT NULL,
  allowed_origins text[] NOT NULL CHECK (cardinality(allowed_origins) BETWEEN 1 AND 20),
  theme jsonb NOT NULL DEFAULT '{}'::jsonb,
  greeting text NOT NULL DEFAULT 'Hi! How can I help you today?',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_widget_sites_tenant ON widget_sites (tenant_id);

-- ------------------------------------------------------------------------------ CRM
CREATE TABLE companies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  domain text,
  industry text,
  size_band text,
  owner_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX ix_companies_tenant_name ON companies (tenant_id, lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_companies_tenant_domain ON companies (tenant_id, lower(domain))
  WHERE domain IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  company_id uuid REFERENCES companies(id),
  full_name text,
  email_ciphertext text,
  email_hash varchar(64),
  phone_ciphertext text,
  phone_hash varchar(64),
  whatsapp_hash varchar(64),
  preferred_channel text CHECK (preferred_channel IS NULL OR preferred_channel IN ('web','whatsapp','email','phone')),
  timezone text,
  communication_preferences jsonb NOT NULL DEFAULT '{}'::jsonb,
  consent jsonb NOT NULL DEFAULT '{}'::jsonb,
  source text,
  source_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  owner_id uuid REFERENCES users(id),
  last_interaction_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX uq_contacts_tenant_email ON contacts (tenant_id, email_hash)
  WHERE email_hash IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX ix_contacts_tenant_phone ON contacts (tenant_id, phone_hash) WHERE deleted_at IS NULL;
CREATE INDEX ix_contacts_tenant_whatsapp ON contacts (tenant_id, whatsapp_hash) WHERE deleted_at IS NULL;
CREATE INDEX ix_contacts_tenant_last ON contacts (tenant_id, last_interaction_at DESC);

CREATE TABLE opportunities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  contact_id uuid REFERENCES contacts(id),
  company_id uuid REFERENCES companies(id),
  title text NOT NULL,
  stage text NOT NULL DEFAULT 'NEW_LEAD' CHECK (stage IN ('NEW_LEAD','QUALIFIED','APPOINTMENT_BOOKED',
    'SECURITY_REVIEW','PROPOSAL','NEGOTIATION','WON','LOST')),
  lead_owner_id uuid REFERENCES users(id),
  estimated_value numeric(14,2) CHECK (estimated_value IS NULL OR estimated_value >= 0),
  currency varchar(3) NOT NULL DEFAULT 'USD',
  source text,
  source_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  qualification jsonb NOT NULL DEFAULT '{}'::jsonb,
  service_interest text,
  next_action text,
  next_action_at timestamptz,
  last_interaction_at timestamptz,
  lost_reason text,
  stage_changed_at timestamptz NOT NULL DEFAULT now(),
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX ix_opportunities_tenant_stage ON opportunities (tenant_id, stage) WHERE deleted_at IS NULL;
CREATE INDEX ix_opportunities_tenant_contact ON opportunities (tenant_id, contact_id);
CREATE INDEX ix_opportunities_tenant_owner ON opportunities (tenant_id, lead_owner_id);

CREATE TABLE crm_activities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  contact_id uuid REFERENCES contacts(id),
  opportunity_id uuid REFERENCES opportunities(id),
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  activity_type text NOT NULL,
  summary text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_crm_activities_tenant_contact ON crm_activities (tenant_id, contact_id, occurred_at DESC);
CREATE INDEX ix_crm_activities_tenant_opp ON crm_activities (tenant_id, opportunity_id, occurred_at DESC);

CREATE TABLE crm_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  contact_id uuid REFERENCES contacts(id),
  opportunity_id uuid REFERENCES opportunities(id),
  author_type text NOT NULL,
  author_id text NOT NULL,
  body text NOT NULL CHECK (length(body) <= 20000),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX ix_crm_notes_tenant_contact ON crm_notes (tenant_id, contact_id);

CREATE TABLE crm_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  contact_id uuid REFERENCES contacts(id),
  opportunity_id uuid REFERENCES opportunities(id),
  assignee_id uuid REFERENCES users(id),
  title text NOT NULL,
  due_at timestamptz,
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','DONE','CANCELLED')),
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_crm_tasks_tenant_due ON crm_tasks (tenant_id, status, due_at);

-- ------------------------------------------------------------------------ conversations
CREATE TABLE conversations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  contact_id uuid REFERENCES contacts(id),
  channel text NOT NULL CHECK (channel IN ('web','whatsapp','email')),
  external_ref_hash varchar(64) NOT NULL,
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','ESCALATED','HUMAN_HANDLING','CLOSED')),
  assigned_user_id uuid REFERENCES users(id),
  summary text,
  escalation_reason text,
  last_message_at timestamptz,
  last_inbound_at timestamptz,
  context jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_conversations_ref UNIQUE (tenant_id, channel, external_ref_hash)
);
CREATE INDEX ix_conversations_tenant_status ON conversations (tenant_id, status, last_message_at DESC);

CREATE TABLE messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  direction text NOT NULL CHECK (direction IN ('inbound','outbound')),
  sender_type text NOT NULL CHECK (sender_type IN ('customer','samiir','human_agent','system')),
  sender_id text,
  content text NOT NULL CHECK (length(content) <= 8000),
  content_type text NOT NULL DEFAULT 'text',
  cards jsonb NOT NULL DEFAULT '[]'::jsonb,
  external_message_id text,
  delivery_status text,
  injection_score numeric(4,3),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_messages_external ON messages (tenant_id, external_message_id)
  WHERE external_message_id IS NOT NULL;
CREATE INDEX ix_messages_conversation ON messages (tenant_id, conversation_id, created_at);

-- -------------------------------------------------------------------------- scheduling
CREATE TABLE appointment_types (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  code text NOT NULL CHECK (code ~ '^[a-z0-9_-]{2,64}$'),
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  duration_minutes integer NOT NULL CHECK (duration_minutes BETWEEN 5 AND 480),
  buffer_minutes integer NOT NULL DEFAULT 0 CHECK (buffer_minutes BETWEEN 0 AND 240),
  calendar_integration_id uuid REFERENCES integrations(id),
  calendar_id text NOT NULL DEFAULT 'primary',
  rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_appointment_types_code UNIQUE (tenant_id, code)
);

CREATE TABLE appointments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  appointment_type_id uuid NOT NULL REFERENCES appointment_types(id),
  contact_id uuid REFERENCES contacts(id),
  opportunity_id uuid REFERENCES opportunities(id),
  conversation_id uuid REFERENCES conversations(id),
  provider text NOT NULL CHECK (provider IN ('google','microsoft365','local')),
  calendar_id text NOT NULL,
  external_event_id text,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  timezone text NOT NULL,
  status text NOT NULL DEFAULT 'BOOKED' CHECK (status IN ('BOOKED','CANCELLED','RESCHEDULED',
    'COMPLETED','NO_SHOW','FAILED')),
  idempotency_key text NOT NULL,
  rescheduled_from_id uuid REFERENCES appointments(id),
  created_by_type text NOT NULL,
  created_by_id text NOT NULL,
  cancelled_at timestamptz,
  cancellation_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (ends_at > starts_at),
  CONSTRAINT uq_appointments_idempotency UNIQUE (tenant_id, idempotency_key),
  -- The database itself refuses double-booking of the same calendar.
  CONSTRAINT ex_appointments_no_overlap EXCLUDE USING gist (
    tenant_id WITH =, calendar_id WITH =, tstzrange(starts_at, ends_at, '[)') WITH &&
  ) WHERE (status = 'BOOKED')
);
CREATE INDEX ix_appointments_tenant_start ON appointments (tenant_id, starts_at);
CREATE INDEX ix_appointments_tenant_contact ON appointments (tenant_id, contact_id);

-- --------------------------------------------------------------------------- knowledge
CREATE TABLE knowledge_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  lineage_id uuid NOT NULL,
  title text NOT NULL CHECK (length(title) <= 300),
  content text NOT NULL CHECK (length(content) <= 200000),
  category text NOT NULL CHECK (category IN ('company_profile','services','products','pricing','faq',
    'onboarding','service_scope','included','excluded','delivery_timeline','support_procedures',
    'customer_service_policies','appointment_rules','sales_qualification_rules',
    'refund_escalation_policies','security_services','legal_approved_messaging')),
  source text NOT NULL,
  visibility text NOT NULL DEFAULT 'internal' CHECK (visibility IN ('public','internal')),
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','PENDING_APPROVAL','APPROVED','ARCHIVED')),
  structured_data jsonb,
  content_hash varchar(64) NOT NULL,
  injection_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_by uuid REFERENCES users(id),
  approved_by uuid REFERENCES users(id),
  approved_at timestamptz,
  effective_date timestamptz,
  review_date timestamptz,
  expiration_date timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT uq_knowledge_lineage_version UNIQUE (tenant_id, lineage_id, version),
  CHECK (status <> 'APPROVED' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
-- Only one approved version per lineage at a time.
CREATE UNIQUE INDEX uq_knowledge_one_approved ON knowledge_documents (tenant_id, lineage_id)
  WHERE status = 'APPROVED' AND deleted_at IS NULL;
CREATE INDEX ix_knowledge_documents_lookup ON knowledge_documents (tenant_id, status, visibility, category);

CREATE TABLE knowledge_chunks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  document_id uuid NOT NULL REFERENCES knowledge_documents(id) ON DELETE CASCADE,
  chunk_index integer NOT NULL,
  content text NOT NULL,
  embedding vector(1536),
  embedding_model text NOT NULL,
  tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_knowledge_chunks_doc_idx UNIQUE (document_id, chunk_index)
);
CREATE INDEX ix_knowledge_chunks_embedding ON knowledge_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ix_knowledge_chunks_tsv ON knowledge_chunks USING gin (tsv);
CREATE INDEX ix_knowledge_chunks_tenant_doc ON knowledge_chunks (tenant_id, document_id);

-- ----------------------------------------------------------------------- notifications
CREATE TABLE notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  channel text NOT NULL CHECK (channel IN ('email','whatsapp','slack')),
  template text NOT NULL,
  contact_id uuid REFERENCES contacts(id),
  recipient_user_id uuid REFERENCES users(id),
  variables jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED','SENDING','SENT','DELIVERED',
    'READ','FAILED','CANCELLED')),
  scheduled_for timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  provider_message_id text,
  idempotency_key text NOT NULL,
  related_type text,
  related_id uuid,
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_notifications_idempotency UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX ix_notifications_due ON notifications (scheduled_for) WHERE status = 'SCHEDULED';
CREATE INDEX ix_notifications_related ON notifications (tenant_id, related_type, related_id);
CREATE INDEX ix_notifications_provider_id ON notifications (provider_message_id)
  WHERE provider_message_id IS NOT NULL;

-- ---------------------------------------------------------------------------- security
CREATE TABLE assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  asset_type text NOT NULL DEFAULT 'website' CHECK (asset_type IN ('website','api','host','dns','cdn_zone','application')),
  canonical_target text NOT NULL CHECK (canonical_target ~ '^[a-z0-9.-]+$'),
  environment text NOT NULL DEFAULT 'production',
  criticality smallint NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
  owner text,
  tags text[] NOT NULL DEFAULT '{}'::text[],
  allowlisted boolean NOT NULL DEFAULT false,
  verification_status text NOT NULL DEFAULT 'UNVERIFIED' CHECK (verification_status IN
    ('UNVERIFIED','PENDING','VERIFIED','EXPIRED','FAILED')),
  verified_until timestamptz,
  customer_authorization_ref text,
  customer_authorization_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  -- An asset can only be allowlisted for scanning after ownership verification.
  CHECK (NOT allowlisted OR verification_status = 'VERIFIED')
);
CREATE UNIQUE INDEX uq_assets_tenant_target ON assets (tenant_id, canonical_target) WHERE deleted_at IS NULL;

CREATE TABLE asset_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  method text NOT NULL CHECK (method IN ('dns_txt','http_file')),
  challenge_token_hash varchar(64) NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','VERIFIED','FAILED','EXPIRED')),
  requested_by text NOT NULL,
  checked_at timestamptz,
  verified_at timestamptz,
  expires_at timestamptz NOT NULL,
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_asset_verifications_asset ON asset_verifications (tenant_id, asset_id, created_at DESC);

CREATE TABLE security_events (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  asset_id uuid REFERENCES assets(id),
  source text NOT NULL,
  event_type text NOT NULL,
  category text NOT NULL,
  severity smallint NOT NULL CHECK (severity BETWEEN 0 AND 10),
  confidence numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  "timestamp" timestamptz NOT NULL,
  src_ip inet,
  destination text,
  request_path text CHECK (length(request_path) <= 2048),
  http_method text,
  status_code smallint,
  user_id text,
  country varchar(2),
  user_agent text CHECK (length(user_agent) <= 512),
  signature text,
  rule_id text,
  action_taken text,
  risk text,
  metadata_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
  raw_event_reference text,
  dedupe_key varchar(64) NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_security_events_dedupe UNIQUE (tenant_id, dedupe_key)
);
CREATE INDEX ix_security_events_tenant_time ON security_events (tenant_id, "timestamp" DESC);
CREATE INDEX ix_security_events_tenant_cat ON security_events (tenant_id, category, "timestamp" DESC);
CREATE INDEX ix_security_events_tenant_ip ON security_events (tenant_id, src_ip, "timestamp" DESC);
CREATE INDEX ix_security_events_asset ON security_events (tenant_id, asset_id, "timestamp" DESC);

CREATE TABLE incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  title text NOT NULL,
  summary text NOT NULL DEFAULT '',
  category text NOT NULL,
  asset_id uuid REFERENCES assets(id),
  risk_level text NOT NULL CHECK (risk_level IN ('NORMAL','SUSPICIOUS','HIGH RISK','CRITICAL')),
  risk_score smallint NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  claim_status text NOT NULL DEFAULT 'SUSPECTED INCIDENT' CHECK (claim_status IN
    ('SUSPECTED INCIDENT','CONFIRMED INCIDENT')),
  status text NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','CONTAINED',
    'REMEDIATED','CLOSED','FALSE_POSITIVE')),
  correlation_key varchar(64) NOT NULL,
  event_count integer NOT NULL DEFAULT 0,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  signals jsonb NOT NULL DEFAULT '[]'::jsonb,
  recommendations jsonb NOT NULL DEFAULT '[]'::jsonb,
  analysis jsonb NOT NULL DEFAULT '{}'::jsonb,
  assignee_id uuid REFERENCES users(id),
  acknowledged_at timestamptz,
  contained_at timestamptz,
  resolved_at timestamptz,
  confirmed_by uuid REFERENCES users(id),
  confirmed_at timestamptz,
  confirmation_evidence jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- A breach/incident can only be CONFIRMED by a named human with recorded evidence.
  CONSTRAINT ck_incidents_confirmation_requires_evidence CHECK (
    claim_status <> 'CONFIRMED INCIDENT'
    OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL AND confirmation_evidence IS NOT NULL)
  )
);
CREATE INDEX ix_incidents_tenant_status ON incidents (tenant_id, status, risk_score DESC);
CREATE UNIQUE INDEX uq_incidents_open_correlation ON incidents (tenant_id, correlation_key)
  WHERE status NOT IN ('CLOSED','FALSE_POSITIVE');

CREATE TABLE incident_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  security_event_id uuid REFERENCES security_events(event_id),
  entry_type text NOT NULL CHECK (entry_type IN ('event_linked','status_change','note','analysis',
    'recommendation','action','confirmation','assignment')),
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  body jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_incident_events_incident ON incident_events (tenant_id, incident_id, created_at);
CREATE UNIQUE INDEX uq_incident_events_link ON incident_events (incident_id, security_event_id)
  WHERE security_event_id IS NOT NULL;

CREATE TABLE approval_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  action_type text NOT NULL,
  action_payload jsonb NOT NULL,
  payload_hash varchar(64) NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  target_type text,
  target_id uuid,
  requested_by text NOT NULL,
  requested_by_type text NOT NULL,
  requested_via text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL,
  risk_level text NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED',
    'EXECUTED','CANCELLED')),
  approved_by text,
  approved_at timestamptz,
  decision_comment text,
  approval_signature text,
  consumed_at timestamptz,
  consumed_by text,
  CHECK (expires_at > requested_at),
  -- Four-eyes: the requester can never approve their own request.
  CONSTRAINT ck_approval_requests_four_eyes CHECK (approved_by IS NULL OR approved_by <> requested_by)
);
CREATE INDEX ix_approval_requests_tenant_status ON approval_requests (tenant_id, status, requested_at DESC);

CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  target_url text NOT NULL,
  requested_by text NOT NULL,
  approval_id uuid REFERENCES approval_requests(id),
  authorization_ticket text NOT NULL CHECK (authorization_ticket ~ '^[A-Za-z0-9._#/-]{3,64}$'),
  customer_authorization_ref text NOT NULL,
  profile text NOT NULL CHECK (profile IN ('safe-passive','safe-standard')),
  scanners text[] NOT NULL,
  status text NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (status IN ('PENDING_APPROVAL','APPROVED','QUEUED',
    'RUNNING','SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','REJECTED')),
  workflow_id text,
  idempotency_key text NOT NULL,
  scheduled_for timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  timeout_seconds integer NOT NULL DEFAULT 3600 CHECK (timeout_seconds BETWEEN 60 AND 21600),
  attempt integer NOT NULL DEFAULT 1,
  retry_of_id uuid REFERENCES scan_jobs(id),
  findings_count integer NOT NULL DEFAULT 0,
  error text,
  scanner_log jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_scan_jobs_idempotency UNIQUE (tenant_id, idempotency_key),
  -- A scan can never leave PENDING_APPROVAL without a linked approval.
  CHECK (status IN ('PENDING_APPROVAL','REJECTED') OR approval_id IS NOT NULL)
);
CREATE INDEX ix_scan_jobs_tenant_status ON scan_jobs (tenant_id, status, created_at DESC);

CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  scan_job_id uuid REFERENCES scan_jobs(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  scanner text NOT NULL,
  rule_id text NOT NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT 'vulnerability',
  severity text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  cvss_score numeric(3,1),
  cwe text,
  url text,
  evidence_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
  remediation text,
  fingerprint varchar(64) NOT NULL,
  false_positive_status text NOT NULL DEFAULT 'UNREVIEWED' CHECK (false_positive_status IN
    ('UNREVIEWED','CONFIRMED_TRUE','FALSE_POSITIVE','ACCEPTED_RISK')),
  remediation_status text NOT NULL DEFAULT 'OPEN' CHECK (remediation_status IN
    ('OPEN','IN_PROGRESS','REMEDIATED','VERIFIED','WONT_FIX')),
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  remediated_at timestamptz,
  reviewed_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_findings_fingerprint UNIQUE (tenant_id, fingerprint)
);
CREATE INDEX ix_findings_tenant_sev ON findings (tenant_id, severity, remediation_status);
CREATE INDEX ix_findings_asset ON findings (tenant_id, asset_id);

CREATE TABLE malware_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  asset_id uuid REFERENCES assets(id),
  filename_sanitized text NOT NULL,
  sha256 varchar(64) NOT NULL,
  sha1 varchar(40) NOT NULL,
  md5 varchar(32) NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  mime_declared text,
  mime_detected text,
  clamav_result text,
  clamav_signature text,
  yara_matches jsonb NOT NULL DEFAULT '[]'::jsonb,
  archive_info jsonb NOT NULL DEFAULT '{}'::jsonb,
  verdict text NOT NULL DEFAULT 'pending' CHECK (verdict IN ('pending','clean','suspicious','malicious','error')),
  quarantine_status text NOT NULL DEFAULT 'QUARANTINED' CHECK (quarantine_status IN ('QUARANTINED','RELEASED','DESTROYED')),
  storage_ref text NOT NULL,
  submitted_by text NOT NULL,
  analyzed_at timestamptz,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_malware_results_tenant ON malware_results (tenant_id, created_at DESC);
CREATE INDEX ix_malware_results_sha256 ON malware_results (tenant_id, sha256);

CREATE TABLE waf_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  incident_id uuid REFERENCES incidents(id),
  approval_id uuid REFERENCES approval_requests(id),
  provider text NOT NULL CHECK (provider IN ('cloudflare','aws_waf','application','none')),
  action_type text NOT NULL,
  target text NOT NULL,
  params jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload_hash varchar(64) NOT NULL,
  risk_level text NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  rationale text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('recommend_only','preapproved_low_risk','human_approved')),
  status text NOT NULL DEFAULT 'RECOMMENDED' CHECK (status IN ('RECOMMENDED','PENDING_APPROVAL','APPROVED',
    'EXECUTING','ACTIVE','EXPIRED','FAILED','REVERTED','REJECTED','DISMISSED')),
  ttl_seconds integer CHECK (ttl_seconds IS NULL OR ttl_seconds BETWEEN 60 AND 604800),
  expires_at timestamptz,
  executed_at timestamptz,
  executed_by text,
  provider_ref text,
  error text,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- Nothing reaches an executing/active state without an approval record, except the
  -- tenant-level pre-approved low-risk mode (which is itself recorded as an approval).
  CHECK (status NOT IN ('EXECUTING','ACTIVE','APPROVED') OR approval_id IS NOT NULL)
);
CREATE INDEX ix_waf_actions_tenant_status ON waf_actions (tenant_id, status, created_at DESC);

-- -------------------------------------------------------------------- agents & audit
CREATE TABLE agent_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  agent_name text NOT NULL CHECK (agent_name IN ('SAMIIR','FATMA')),
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  conversation_id uuid,
  incident_id uuid,
  runtime text NOT NULL,
  model text,
  trace_id text,
  request_id text NOT NULL,
  status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING','COMPLETED','FAILED','BLOCKED')),
  input_tokens integer NOT NULL DEFAULT 0,
  output_tokens integer NOT NULL DEFAULT 0,
  latency_ms integer,
  guardrail_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
  error text,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX ix_agent_runs_tenant ON agent_runs (tenant_id, agent_name, started_at DESC);

CREATE TABLE tool_calls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  agent_run_id uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  agent_name text NOT NULL CHECK (agent_name IN ('SAMIIR','FATMA')),
  tool_name text NOT NULL,
  arguments_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
  arguments_hash varchar(64) NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ALLOWED','DENIED')),
  decision_reason text NOT NULL,
  status text NOT NULL,
  latency_ms integer,
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_tool_calls_run ON tool_calls (tenant_id, agent_run_id);
CREATE INDEX ix_tool_calls_denied ON tool_calls (tenant_id, created_at DESC) WHERE decision = 'DENIED';

CREATE TABLE audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  seq bigint NOT NULL,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  agent_name text,
  agent_run_id uuid,
  service text NOT NULL,
  tool_name text,
  action text NOT NULL,
  target_type text,
  target_id text,
  request_id text NOT NULL,
  source_ip inet,
  result text NOT NULL CHECK (result IN ('success','denied','failure','pending')),
  risk_level text,
  approval_id uuid,
  metadata_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash varchar(64) NOT NULL,
  entry_hash varchar(64) NOT NULL,
  created_at timestamptz NOT NULL,
  CONSTRAINT uq_audit_logs_tenant_seq UNIQUE (tenant_id, seq)
);
CREATE INDEX ix_audit_logs_tenant_time ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX ix_audit_logs_tenant_action ON audit_logs (tenant_id, action, created_at DESC);

-- Audit rows are append-only for everyone, including the schema owner outside migrations.
CREATE FUNCTION app_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$;
CREATE TRIGGER trg_audit_logs_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION app_audit_immutable();

-- Confirmed incident claims can only be *set* together with a human confirmer.
CREATE FUNCTION app_incident_claim_guard() RETURNS trigger LANGUAGE plpgsql AS
$$
BEGIN
  IF NEW.claim_status = 'CONFIRMED INCIDENT' AND
     (OLD.claim_status IS DISTINCT FROM 'CONFIRMED INCIDENT') AND
     current_setting('app.actor', true) NOT LIKE 'user:%' THEN
    RAISE EXCEPTION 'only a human security engineer may confirm an incident';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_incident_claim_guard BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION app_incident_claim_guard();
CREATE FUNCTION app_incident_reject_confirmed_insert() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'incidents are created as SUSPECTED; confirmation is a separate human step'; END $$;
CREATE TRIGGER trg_incident_claim_guard_ins BEFORE INSERT ON incidents
  FOR EACH ROW WHEN (NEW.claim_status = 'CONFIRMED INCIDENT')
  EXECUTE FUNCTION app_incident_reject_confirmed_insert();
"""

UPDATED_AT_TABLES = [
    "tenants", "users", "integrations", "widget_sites", "companies", "contacts", "opportunities",
    "crm_tasks", "conversations", "appointment_types", "appointments", "knowledge_documents",
    "notifications", "assets", "incidents", "scan_jobs", "findings", "malware_results",
    "waf_actions",
]


def upgrade() -> None:
    execute_script(op, SCHEMA)
    for table in UPDATED_AT_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION app_touch_updated_at()"
        )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = app_current_tenant()) "
            f"WITH CHECK (tenant_id = app_current_tenant())"
        )
    op.execute("ALTER TABLE tenants ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenants FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_self ON tenants USING (id = app_current_tenant()) "
               "WITH CHECK (id = app_current_tenant())")


def downgrade() -> None:
    tables = ["audit_logs", "tool_calls", "agent_runs", "waf_actions", "malware_results",
              "findings", "scan_jobs", "approval_requests", "incident_events", "incidents",
              "security_events", "asset_verifications", "assets", "notifications",
              "knowledge_chunks", "knowledge_documents", "appointments", "appointment_types",
              "messages", "conversations", "crm_tasks", "crm_notes", "crm_activities",
              "opportunities", "contacts", "companies", "widget_sites", "integrations",
              "user_roles", "role_permissions", "permissions", "roles", "users", "tenants"]
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs")
    for t in tables:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    for fn in ("app_incident_reject_confirmed_insert", "app_incident_claim_guard", "app_audit_immutable", "app_touch_updated_at",
               "app_current_tenant"):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}() CASCADE")
