/**
 * SQLite Database Initialization & Connection Manager
 * Utilizes better-sqlite3 with WAL mode and foreign key constraints enabled.
 * Database is stored at backend/data/aegismail.db and excluded from Git.
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.resolve(__dirname, '../data');
const DB_PATH = process.env.DATABASE_PATH || path.join(DATA_DIR, 'aegismail.db');

let dbInstance = null;

/**
 * Initializes SQLite database, enables pragmas, and idempotently creates tables and indexes.
 * Calling this multiple times is safe and will not reset existing data.
 */
export function initDatabase(customPath = null) {
  const targetPath = customPath || DB_PATH;

  // Ensure data directory exists
  const parentDir = path.dirname(targetPath);
  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true });
  }

  if (dbInstance) {
    return dbInstance;
  }

  console.log(`[Database] Connecting to SQLite at: ${targetPath}`);
  const db = new Database(targetPath);

  // Performance and integrity pragmas
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Idempotent table schemas
  db.exec(`
    -- 1. Cases Table
    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_number TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- 2. Emails Table
    CREATE TABLE IF NOT EXISTS emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      filename TEXT,
      sha256 TEXT NOT NULL,
      subject TEXT,
      sender TEXT,
      recipient TEXT,
      received_at TEXT,
      raw_email TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    -- 3. Evidence Table (Phase 2 Evidence Model)
    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
      evidence_key TEXT NOT NULL,
      source TEXT NOT NULL,
      field TEXT NOT NULL,
      value TEXT NOT NULL,
      collection_method TEXT NOT NULL,
      collected_at TEXT NOT NULL,
      details TEXT
    );

    -- 4. Findings Table (Phase 2 Finding Model)
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
      finding_key TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      limitations TEXT,
      recommended_action TEXT,
      created_at TEXT NOT NULL
    );

    -- 5. Finding <-> Evidence Many-to-Many Join Table
    CREATE TABLE IF NOT EXISTS finding_evidence (
      finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      PRIMARY KEY (finding_id, evidence_id)
    );

    -- 6. Extracted Threat Indicators Table
    CREATE TABLE IF NOT EXISTS indicators (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      defanged TEXT,
      is_suspicious INTEGER NOT NULL DEFAULT 0,
      details TEXT,
      created_at TEXT NOT NULL
    );

    -- 7. Phase 5 Related Incidents Table
    CREATE TABLE IF NOT EXISTS related_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
      target_email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
      source_case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      target_case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      correlation_score INTEGER NOT NULL,
      relationship_type TEXT NOT NULL DEFAULT 'potentially_related',
      reasons TEXT NOT NULL,
      shared_indicators TEXT NOT NULL,
      created_at TEXT NOT NULL,
      CONSTRAINT check_distinct_emails CHECK (source_email_id <> target_email_id)
    );

    -- 8. Phase 7 Forensic Reports Audit Table
    CREATE TABLE IF NOT EXISTS forensic_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      email_id INTEGER REFERENCES emails(id) ON DELETE SET NULL,
      report_uuid TEXT UNIQUE NOT NULL,
      report_title TEXT NOT NULL,
      export_format TEXT NOT NULL,
      raw_sha256 TEXT NOT NULL,
      dossier_sha256 TEXT NOT NULL,
      generated_at TEXT NOT NULL,
      report_metadata TEXT
    );

    -- Indexes for efficient queries
    CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
    CREATE INDEX IF NOT EXISTS idx_emails_case_id ON emails(case_id);
    CREATE INDEX IF NOT EXISTS idx_emails_sha256 ON emails(sha256);
    CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_email_id ON evidence(email_id);
    CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
    CREATE INDEX IF NOT EXISTS idx_findings_email_id ON findings(email_id);
    CREATE INDEX IF NOT EXISTS idx_finding_evidence_f_id ON finding_evidence(finding_id);
    CREATE INDEX IF NOT EXISTS idx_finding_evidence_e_id ON finding_evidence(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_indicators_case_id ON indicators(case_id);
    CREATE INDEX IF NOT EXISTS idx_indicators_email_id ON indicators(email_id);
    CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(type, value);
    CREATE INDEX IF NOT EXISTS idx_related_source_case ON related_incidents(source_case_id);
    CREATE INDEX IF NOT EXISTS idx_related_target_case ON related_incidents(target_case_id);
    CREATE INDEX IF NOT EXISTS idx_related_source_email ON related_incidents(source_email_id);
    CREATE INDEX IF NOT EXISTS idx_related_target_email ON related_incidents(target_email_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_related_canonical_pair 
      ON related_incidents(
        min(source_email_id, target_email_id),
        max(source_email_id, target_email_id)
      );
    CREATE INDEX IF NOT EXISTS idx_reports_case_id ON forensic_reports(case_id);
    CREATE INDEX IF NOT EXISTS idx_reports_email_id ON forensic_reports(email_id);
    CREATE INDEX IF NOT EXISTS idx_reports_uuid ON forensic_reports(report_uuid);
    CREATE INDEX IF NOT EXISTS idx_reports_raw_sha ON forensic_reports(raw_sha256);
    CREATE INDEX IF NOT EXISTS idx_reports_dossier_sha ON forensic_reports(dossier_sha256);
  `);

  console.log('[Database] Schema verified and indexes created successfully');
  dbInstance = db;
  return dbInstance;
}

/**
 * Returns the current active database instance.
 */
export function getDb() {
  if (!dbInstance) {
    return initDatabase();
  }
  return dbInstance;
}

/**
 * Closes the database connection if open.
 */
export function closeDatabase() {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
    console.log('[Database] Connection closed');
  }
}
