#!/usr/bin/env python3
"""ACCC init_db one-shot initializer.

Runs three tasks in strict order:
  1. Alembic upgrade head  — creates all 12 tables
  2. Seed users            — analyst, senior, manager
  3. Seed ChromaDB         — 4 collections from JSON files (~130+ vectors)

Exits 0 on success, non-zero on failure.
ChromaDB seeding skipped gracefully if OpenAI API key is absent (no embeddings).
"""
import os, sys, json, time, logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [init_db] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
SEED_DIR     = Path("/app/backend/data/seed")
MIGRATIONS   = Path("/app/backend/migrations")

# ── Env ───────────────────────────────────────────────────────────────────────
DATABASE_URL   = os.environ.get("DATABASE_URL") or (
    f"postgresql://{os.environ.get('POSTGRES_USER','accc')}:"
    f"{os.environ.get('POSTGRES_PASSWORD','accc_pass')}@"
    f"postgres:5432/{os.environ.get('POSTGRES_DB','accc_db')}"
)
CHROMADB_HOST  = os.environ.get("CHROMADB_HOST", "chromadb")
CHROMADB_PORT  = int(os.environ.get("CHROMADB_PORT", "8001"))
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 1: Alembic migrations
# ─────────────────────────────────────────────────────────────────────────────
def run_migrations() -> None:
    log.info("=== TASK 1: Running Alembic migrations ===")
    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", str(MIGRATIONS))
    alembic_cfg.set_main_option("sqlalchemy.url", DATABASE_URL)

    command.upgrade(alembic_cfg, "head")
    log.info("Alembic migrations complete.")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 2: Seed users
# ─────────────────────────────────────────────────────────────────────────────
def seed_users() -> None:
    log.info("=== TASK 2: Seeding users ===")
    import bcrypt
    import sqlalchemy as sa

    engine = sa.create_engine(DATABASE_URL)

    SEED_USERS = [
        {"username": "analyst",  "password": "analyst123",  "role": "analyst",        "display_name": "Alice Analyst"},
        {"username": "senior",   "password": "senior123",   "role": "senior_analyst", "display_name": "Sam Senior"},
        {"username": "manager",  "password": "manager123",  "role": "soc_manager",    "display_name": "Mike Manager"},
    ]

    with engine.connect() as conn:
        for u in SEED_USERS:
            existing = conn.execute(
                sa.text("SELECT id FROM users WHERE username = :username"),
                {"username": u["username"]}
            ).fetchone()

            if existing:
                log.info("  User '%s' already exists — skipping.", u["username"])
                continue

            pw_hash = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
            conn.execute(sa.text("""
                INSERT INTO users (username, password_hash, role, display_name)
                VALUES (:username, :password_hash, :role, :display_name)
            """), {
                "username":      u["username"],
                "password_hash": pw_hash,
                "role":          u["role"],
                "display_name":  u["display_name"],
            })
            log.info("  Created user '%s' (role: %s)", u["username"], u["role"])

        conn.commit()
    log.info("User seeding complete.")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 3: Seed ChromaDB
# ─────────────────────────────────────────────────────────────────────────────
def seed_chromadb() -> None:
    log.info("=== TASK 3: Seeding ChromaDB ===")

    if not OPENAI_API_KEY or OPENAI_API_KEY == "your-key-here":
        log.warning("OPENAI_API_KEY not set. Seeding ChromaDB with placeholder embeddings (no AI features until key is set).")
        use_openai = False
    else:
        use_openai = True

    import chromadb
    from chromadb.config import Settings

    # Connect with retry
    client = None
    for attempt in range(10):
        try:
            client = chromadb.HttpClient(
                host=CHROMADB_HOST,
                port=CHROMADB_PORT,
                settings=Settings(anonymized_telemetry=False),
            )
            client.heartbeat()
            log.info("ChromaDB connected (attempt %d)", attempt + 1)
            break
        except Exception as exc:
            log.info("Waiting for ChromaDB... attempt %d/10 (%s)", attempt + 1, exc)
            time.sleep(5)

    if client is None:
        raise RuntimeError("ChromaDB did not become available after 10 attempts")

    # Embedding function
    if use_openai:
        import urllib.request, json as _json
        class _DirectEmbed:
            def name(self):
                return "direct_embed"
            def __call__(self, input):
                payload = _json.dumps({
                    "input": input,
                    "model": "text-embedding-3-small"
                }).encode()
                req = urllib.request.Request(
                    "https://api.openai.com/v1/embeddings",
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {OPENAI_API_KEY}",
                        "Content-Type": "application/json"
                    }
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = _json.loads(resp.read())
                return [item["embedding"] for item in data["data"]]
        embed_fn = _DirectEmbed()
    else:
        # Deterministic placeholder embeddings (384-dim zeros with index noise)
        import hashlib
        class PlaceholderEmbeddings:
            def __call__(self, input):
                results = []
                for text in input:
                    h = int(hashlib.sha256(text.encode()).hexdigest(), 16)
                    vec = [(((h >> i) & 0xFF) / 255.0 - 0.5) for i in range(384)]
                    results.append(vec)
                return results
        embed_fn = PlaceholderEmbeddings()

    # Collection specs: (collection_name, json_file, text_field, metadata_fields)
    collections_spec = [
        ("mitre_techniques", "mitre_techniques.json",  "description",
         ["id", "name", "tactic", "detection", "mitigation"]),
        ("threat_intel",     "threat_intel.json",       "description",
         ["id", "name", "type", "confidence"]),
        ("cve_highlights",   "cve_highlights.json",     "description",
         ["cve_id", "name", "severity", "is_exploited"]),
        ("past_incidents",   "past_incidents.json",     "description",
         ["id", "title", "severity", "attack_type", "resolution"]),
    ]

    for coll_name, filename, text_field, meta_fields in collections_spec:
        seed_file = SEED_DIR / filename
        if not seed_file.exists():
            log.warning("Seed file not found: %s — skipping collection", seed_file)
            continue

        with open(seed_file) as f:
            records = json.load(f)

        # Get or create collection
        try:
            collection = client.get_collection(name=coll_name, embedding_function=embed_fn)
            existing_count = collection.count()
            if existing_count >= len(records):
                log.info("  Collection '%s' already has %d records — skipping.", coll_name, existing_count)
                continue
            log.info("  Collection '%s' has %d/%d records — re-seeding.", coll_name, existing_count, len(records))
            client.delete_collection(name=coll_name)
        except Exception:
            pass

        collection = client.get_or_create_collection(name=coll_name, embedding_function=embed_fn)

        # Batch upsert (ChromaDB limit: 5461 per batch)
        BATCH = 100
        for i in range(0, len(records), BATCH):
            batch = records[i:i+BATCH]
            ids, texts, metas = [], [], []
            for j, rec in enumerate(batch):
                rec_id = rec.get("id") or rec.get("cve_id") or f"{coll_name}-{i+j}"
                text   = str(rec.get(text_field, "")) or str(rec)
                meta   = {k: str(rec[k]) if isinstance(rec.get(k), (bool, list)) else rec.get(k, "")
                          for k in meta_fields if k in rec}
                ids.append(str(rec_id))
                texts.append(text)
                metas.append(meta)

            collection.upsert(ids=ids, documents=texts, metadatas=metas)
            log.info("    Upserted batch %d-%d into '%s'", i, i+len(batch)-1, coll_name)

        log.info("  Collection '%s': %d documents seeded.", coll_name, collection.count())

    log.info("ChromaDB seeding complete.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    log.info("ACCC init_db starting...")
    log.info("DATABASE_URL: postgresql://...@postgres:5432/%s", os.environ.get("POSTGRES_DB", "accc_db"))

    # Wait for postgres to be genuinely ready
    import sqlalchemy as sa
    engine = sa.create_engine(DATABASE_URL)
    for attempt in range(30):
        try:
            with engine.connect() as conn:
                conn.execute(sa.text("SELECT 1"))
            log.info("PostgreSQL is ready.")
            break
        except Exception as exc:
            log.info("Waiting for postgres... attempt %d/30 (%s)", attempt + 1, exc)
            time.sleep(2)
    else:
        log.error("PostgreSQL did not become ready in 60 seconds.")
        sys.exit(1)

    try:
        run_migrations()
        seed_users()
        seed_chromadb()
    except Exception as exc:
        log.exception("init_db failed: %s", exc)
        sys.exit(1)

    log.info("=== init_db completed successfully ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
