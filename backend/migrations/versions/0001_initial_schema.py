"""Initial schema — all 12 ACCC tables

Revision ID: 0001
Revises:
Create Date: 2026-03-01 00:00:00.000000

Core (G-01):  users, events, incidents, assets, response_actions, hunt_results
v2 New:       conversations, analyst_feedback, entity_graph, security_audit,
              ip_reputation_cache, cve_cache
"""
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # 1. users
    op.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        username      VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role          VARCHAR(20)  NOT NULL DEFAULT 'analyst',
        display_name  VARCHAR(255),
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        last_login    TIMESTAMPTZ,
        preferences   JSONB        NOT NULL DEFAULT '{}'
    )""")

    # 2. incidents (before events so FK works)
    op.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id                         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        title                      VARCHAR(500) NOT NULL,
        description                TEXT,
        severity                   VARCHAR(10)  NOT NULL,
        status                     VARCHAR(20)  NOT NULL DEFAULT 'open',
        created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        resolved_at                TIMESTAMPTZ,
        assigned_to                UUID REFERENCES users(id) ON DELETE SET NULL,
        event_count                INTEGER      NOT NULL DEFAULT 0,
        affected_assets            TEXT[]       NOT NULL DEFAULT '{}',
        affected_users             TEXT[]       NOT NULL DEFAULT '{}',
        ioc_ips                    INET[]       NOT NULL DEFAULT '{}',
        ioc_domains                TEXT[]       NOT NULL DEFAULT '{}',
        ioc_hashes                 TEXT[]       NOT NULL DEFAULT '{}',
        mitre_tactics              TEXT[]       NOT NULL DEFAULT '{}',
        mitre_techniques           TEXT[]       NOT NULL DEFAULT '{}',
        kill_chain_stage           VARCHAR(50),
        attack_type                VARCHAR(100),
        ai_summary                 TEXT,
        ai_recommendations         JSONB        NOT NULL DEFAULT '[]',
        confidence_score           FLOAT,
        false_positive_probability FLOAT,
        is_campaign                BOOLEAN      NOT NULL DEFAULT FALSE,
        campaign_id                UUID REFERENCES incidents(id) ON DELETE SET NULL,
        stix_bundle                JSONB,
        report_generated_at        TIMESTAMPTZ
    )""")

    # 3. events — 33 columns (G-01 CRITICAL)
    op.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        timestamp         TIMESTAMPTZ  NOT NULL,
        ingested_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        source_format     VARCHAR(20),
        source_identifier VARCHAR(255),
        event_type        VARCHAR(100),
        severity          VARCHAR(10)  NOT NULL DEFAULT 'MEDIUM',
        raw_log           TEXT,
        src_ip            INET,
        dst_ip            INET,
        src_port          INTEGER,
        dst_port          INTEGER,
        protocol          VARCHAR(10),
        username          VARCHAR(255),
        hostname          VARCHAR(255),
        process_name      VARCHAR(255),
        file_hash         VARCHAR(128),
        action            VARCHAR(50),
        rule_id           VARCHAR(100),
        geo_country       VARCHAR(2),
        geo_city          VARCHAR(100),
        geo_lat           FLOAT,
        geo_lon           FLOAT,
        abuse_score       INTEGER      CHECK (abuse_score IS NULL OR (abuse_score >= 0 AND abuse_score <= 100)),
        relevant_cves     TEXT[]       NOT NULL DEFAULT '{}',
        mitre_tactic      VARCHAR(100),
        mitre_technique   VARCHAR(20),
        severity_score    FLOAT,
        is_false_positive BOOLEAN      NOT NULL DEFAULT FALSE,
        incident_id       UUID REFERENCES incidents(id) ON DELETE SET NULL,
        triage_status     VARCHAR(20)  NOT NULL DEFAULT 'pending',
        ai_triage_notes   TEXT,
        tags              TEXT[]       NOT NULL DEFAULT '{}'
    )""")

    # 4. assets — 12 columns (G-01)
    op.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        hostname           VARCHAR(255) UNIQUE NOT NULL,
        ip_address         INET,
        asset_type         VARCHAR(50)  NOT NULL DEFAULT 'server',
        criticality        VARCHAR(10)  NOT NULL DEFAULT 'medium',
        owner              VARCHAR(255),
        os                 VARCHAR(100),
        tags               TEXT[]       NOT NULL DEFAULT '{}',
        is_internet_facing BOOLEAN      NOT NULL DEFAULT FALSE,
        last_seen          TIMESTAMPTZ,
        notes              TEXT,
        created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    )""")

    # 5. response_actions — 19 columns (G-01 / G-05)
    op.execute("""
    CREATE TABLE IF NOT EXISTS response_actions (
        id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        incident_id        UUID         NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        action_type        VARCHAR(50)  NOT NULL,
        action_params      JSONB        NOT NULL DEFAULT '{}',
        risk_level         VARCHAR(10)  NOT NULL,
        status             VARCHAR(20)  NOT NULL DEFAULT 'pending',
        created_by         VARCHAR(20)  NOT NULL DEFAULT 'ai',
        requested_by       UUID REFERENCES users(id) ON DELETE SET NULL,
        approved_by        UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        approved_at        TIMESTAMPTZ,
        executed_at        TIMESTAMPTZ,
        completed_at       TIMESTAMPTZ,
        veto_deadline      TIMESTAMPTZ,
        result             TEXT,
        rollback_available BOOLEAN      NOT NULL DEFAULT TRUE,
        rolled_back_at     TIMESTAMPTZ,
        simulation_mode    BOOLEAN      NOT NULL DEFAULT TRUE,
        audit_log          JSONB        NOT NULL DEFAULT '[]'
    )""")

    # 6. hunt_results — 14 columns (G-01)
    op.execute("""
    CREATE TABLE IF NOT EXISTS hunt_results (
        id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        hunt_id           UUID         NOT NULL,
        hypothesis        TEXT         NOT NULL,
        triggered_by      VARCHAR(20)  NOT NULL DEFAULT 'scheduled',
        findings          JSONB        NOT NULL DEFAULT '[]',
        react_transcript  JSONB        NOT NULL DEFAULT '[]',
        severity          VARCHAR(10),
        confidence        FLOAT,
        event_count       INTEGER      NOT NULL DEFAULT 0,
        matched_event_ids UUID[]       NOT NULL DEFAULT '{}',
        mitre_techniques  TEXT[]       NOT NULL DEFAULT '{}',
        status            VARCHAR(20)  NOT NULL DEFAULT 'active',
        created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        completed_at      TIMESTAMPTZ
    )""")

    # 7. conversations (v2 — F-03 persistent chat)
    op.execute("""
    CREATE TABLE IF NOT EXISTS conversations (
        id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        analyst_id          UUID REFERENCES users(id) ON DELETE CASCADE,
        created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        title               VARCHAR(255),
        messages            JSONB        NOT NULL DEFAULT '[]',
        related_incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL
    )""")

    # 8. analyst_feedback (v2 — F-21 learning loop)
    op.execute("""
    CREATE TABLE IF NOT EXISTS analyst_feedback (
        id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        analyst_id      UUID REFERENCES users(id) ON DELETE SET NULL,
        event_id        UUID REFERENCES events(id)  ON DELETE CASCADE,
        incident_id     UUID REFERENCES incidents(id) ON DELETE CASCADE,
        ai_verdict      VARCHAR(20),
        analyst_verdict VARCHAR(20)  NOT NULL,
        ai_confidence   FLOAT,
        notes           TEXT,
        created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    )""")

    # 9. entity_graph (v2 — F-19)
    op.execute("""
    CREATE TABLE IF NOT EXISTS entity_graph (
        id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        source_entity_type  VARCHAR(30)  NOT NULL,
        source_entity_value VARCHAR(255) NOT NULL,
        target_entity_type  VARCHAR(30)  NOT NULL,
        target_entity_value VARCHAR(255) NOT NULL,
        relationship_type   VARCHAR(50)  NOT NULL,
        interaction_count   INTEGER      NOT NULL DEFAULT 1,
        risk_score          FLOAT,
        evidence_event_ids  UUID[]       NOT NULL DEFAULT '{}',
        first_seen          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        last_seen           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    )""")

    # 10. security_audit (v2 — F-03 injection defense log)
    op.execute("""
    CREATE TABLE IF NOT EXISTS security_audit (
        id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        timestamp  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        event_type VARCHAR(50)  NOT NULL,
        analyst_id UUID REFERENCES users(id) ON DELETE SET NULL,
        source_ip  INET,
        details    JSONB        NOT NULL DEFAULT '{}'
    )""")

    # 11. ip_reputation_cache
    op.execute("""
    CREATE TABLE IF NOT EXISTS ip_reputation_cache (
        ip          INET         PRIMARY KEY,
        abuse_score INTEGER,
        is_tor      BOOLEAN      NOT NULL DEFAULT FALSE,
        is_vpn      BOOLEAN      NOT NULL DEFAULT FALSE,
        country     VARCHAR(50),
        isp         VARCHAR(255),
        cached_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    )""")

    # 12. cve_cache
    op.execute("""
    CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id            VARCHAR(20) PRIMARY KEY,
        cvss_score        FLOAT,
        cvss_v3_score     FLOAT,
        severity          VARCHAR(10),
        is_exploited      BOOLEAN     NOT NULL DEFAULT FALSE,
        affected_products JSONB       NOT NULL DEFAULT '[]',
        description       TEXT,
        published_date    DATE,
        cached_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""")

    # Indexes
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp     ON events (timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_severity      ON events (severity)",
        "CREATE INDEX IF NOT EXISTS idx_events_triage_status ON events (triage_status)",
        "CREATE INDEX IF NOT EXISTS idx_events_incident_id   ON events (incident_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_src_ip        ON events USING GIST (src_ip inet_ops)",
        "CREATE INDEX IF NOT EXISTS idx_events_event_type    ON events (event_type)",
        "CREATE INDEX IF NOT EXISTS idx_events_ingested_at   ON events (ingested_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents (status)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents (severity)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_hunt_results_hunt_id ON hunt_results (hunt_id)",
        "CREATE INDEX IF NOT EXISTS idx_entity_graph_src     ON entity_graph (source_entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_entity_graph_tgt     ON entity_graph (target_entity_value)",
        "CREATE INDEX IF NOT EXISTS idx_conversations_analyst ON conversations (analyst_id)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_analyst     ON analyst_feedback (analyst_id)",
    ]:
        op.execute(idx_sql)


def downgrade() -> None:
    for t in ['cve_cache', 'ip_reputation_cache', 'security_audit',
              'entity_graph', 'analyst_feedback', 'conversations',
              'hunt_results', 'response_actions', 'assets',
              'events', 'incidents', 'users']:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
#phase 6 
    # 6. hunt_results — patched Phase 6 schema (F-14 / G-03)
    op.execute("""
    CREATE TABLE IF NOT EXISTS hunt_results (
        id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
        hunt_id            UUID         NOT NULL,
        hypothesis         TEXT         NOT NULL,
        triggered_by       VARCHAR(20)  NOT NULL DEFAULT 'scheduled',
        analyst_id         UUID REFERENCES users(id) ON DELETE SET NULL,
        started_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        completed_at       TIMESTAMPTZ,
        status             VARCHAR(20)  NOT NULL DEFAULT 'running',
        events_examined    INTEGER      NOT NULL DEFAULT 0,
        findings_count     INTEGER      NOT NULL DEFAULT 0,
        findings           JSONB        NOT NULL DEFAULT '[]',
        ai_narrative       TEXT,
        technique_coverage TEXT[]       NOT NULL DEFAULT '{}',
        react_transcript   JSONB        NOT NULL DEFAULT '[]'
    )""")