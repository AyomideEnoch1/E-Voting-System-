/**
 * Database — MySQL connection pool + auto table creation
 */
require('dotenv').config();
const mysql = require('mysql2/promise');

let db;

async function connectDB() {
  try {
    db = await mysql.createPool({
      host:             process.env.DB_HOST || 'localhost',
      port:             process.env.DB_PORT || 3306,
      user:             process.env.DB_USER || 'root',
      password:         process.env.DB_PASS || '',
      database:         process.env.DB_NAME || 'evoting',
      waitForConnections: true,
      connectionLimit:  10,
      timezone:         '+01:00'
    });

    db.pool.on('connection', (conn) => {
      conn.query("SET time_zone = '+01:00'");
    });

    await db.query('SELECT 1');
    console.log('✅  MySQL connected');
    await createTables();
    await runMigrations();
  } catch (err) {
    console.error('❌  MySQL connection failed:', err.message);
    process.exit(1);
  }
}

async function createTables() {
  const tables = [

    /* ── USERS ── */
    `CREATE TABLE IF NOT EXISTS users (
      id                           VARCHAR(36)  PRIMARY KEY,
      full_name                    VARCHAR(150) NOT NULL,
      email                        VARCHAR(150) NOT NULL UNIQUE,
      voter_id                     VARCHAR(50)  UNIQUE,
      password_hash                VARCHAR(255) NOT NULL,
      role                         ENUM('voter','admin','observer') DEFAULT 'voter',
      is_active                    TINYINT(1)   DEFAULT 1,
      is_verified                  TINYINT(1)   DEFAULT 0,
      public_key                   TEXT,
      login_attempts               INT          DEFAULT 0,
      locked_until                 DATETIME,
      last_login                   DATETIME,
      verification_token           VARCHAR(36),
      verification_token_expiry    DATETIME,
      created_at                   DATETIME     DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── ELECTIONS ── */
    `CREATE TABLE IF NOT EXISTS elections (
      id             VARCHAR(36)  PRIMARY KEY,
      title          VARCHAR(255) NOT NULL,
      description    TEXT,
      start_time     DATETIME     NOT NULL,
      end_time       DATETIME     NOT NULL,
      status         ENUM('draft','active','closed','tallied') DEFAULT 'draft',
      master_key_enc TEXT,
      public_key     TEXT,
      results_sig    TEXT,
      created_by     VARCHAR(36)  NOT NULL,
      created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── CANDIDATES ── */
    `CREATE TABLE IF NOT EXISTS candidates (
      id               VARCHAR(36)  PRIMARY KEY,
      election_id      VARCHAR(36)  NOT NULL,
      name             VARCHAR(150) NOT NULL,
      party            VARCHAR(100),
      position         VARCHAR(100),
      age              INT,
      gender           VARCHAR(20),
      state_of_origin  VARCHAR(100),
      education        TEXT,
      experience       TEXT,
      bio              TEXT,
      manifesto        LONGTEXT,
      photo_url        VARCHAR(500) DEFAULT '',
      manifesto_doc    VARCHAR(500) DEFAULT '',
      extra_docs       TEXT,
      sort_order       INT          DEFAULT 0,
      created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
      updated_at       DATETIME     ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── VOTES (encrypted, anonymous) ── */
    `CREATE TABLE IF NOT EXISTS votes (
      id             VARCHAR(36) PRIMARY KEY,
      election_id    VARCHAR(36) NOT NULL,
      anonymous_id   VARCHAR(64) NOT NULL,
      encrypted_vote TEXT        NOT NULL,
      vote_iv        VARCHAR(64) NOT NULL,
      vote_tag       VARCHAR(64) NOT NULL,
      vote_hash      VARCHAR(64) NOT NULL,
      receipt_hash   VARCHAR(64) NOT NULL,
      receipt_sig    TEXT        NOT NULL,
      receipt_data   TEXT        NOT NULL,
      cast_at        DATETIME    DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_vote (election_id, anonymous_id),
      FOREIGN KEY (election_id) REFERENCES elections(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── VOTE REGISTRY ── */
    `CREATE TABLE IF NOT EXISTS vote_registry (
      id          VARCHAR(36) PRIMARY KEY,
      voter_id    VARCHAR(36) NOT NULL,
      election_id VARCHAR(36) NOT NULL,
      voted_at    DATETIME    DEFAULT CURRENT_TIMESTAMP,
      ip_hash     VARCHAR(32),
      UNIQUE KEY uq_registry (voter_id, election_id),
      FOREIGN KEY (voter_id)    REFERENCES users(id),
      FOREIGN KEY (election_id) REFERENCES elections(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── AUDIT LOG ── */
    `CREATE TABLE IF NOT EXISTS audit_log (
      id         VARCHAR(36)  PRIMARY KEY,
      action     VARCHAR(100) NOT NULL,
      user_id    VARCHAR(36),
      meta       TEXT,
      ip_hash    VARCHAR(32),
      created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── ELECTION RESULTS ── */
    `CREATE TABLE IF NOT EXISTS election_results (
      id          VARCHAR(36) PRIMARY KEY,
      election_id VARCHAR(36) NOT NULL UNIQUE,
      results     TEXT        NOT NULL,
      signature   TEXT        NOT NULL,
      tallied_by  VARCHAR(36) NOT NULL,
      tallied_at  DATETIME    DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (election_id) REFERENCES elections(id),
      FOREIGN KEY (tallied_by)  REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── VOTER ID RESET REQUESTS ── */
    `CREATE TABLE IF NOT EXISTS voter_id_reset_requests (
      id          VARCHAR(36)  PRIMARY KEY,
      user_id     VARCHAR(36)  NOT NULL,
      reason      TEXT,
      status      ENUM('pending','approved','rejected') DEFAULT 'pending',
      admin_note  TEXT,
      reviewed_by VARCHAR(36),
      reviewed_at DATETIME,
      created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (reviewed_by) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  ];

  for (const sql of tables) await db.query(sql);
  console.log('✅  All tables ready');
}

/* ── Add receipt_data column to existing votes table if missing ── */
async function runMigrations() {
  try {
    await db.query(`ALTER TABLE votes ADD COLUMN IF NOT EXISTS receipt_data TEXT NOT NULL DEFAULT ''`);
    console.log('✅  Migrations complete');
  } catch (e) {
    // Ignore — column may already exist or DB doesn't support IF NOT EXISTS
  }
}

const q  = (sql, p = []) => db.query(sql, p);
const q1 = async (sql, p = []) => { const [r] = await db.query(sql, p); return r[0] || null; };
const qa = async (sql, p = []) => { const [r] = await db.query(sql, p); return r; };

module.exports = { connectDB, q, q1, qa };
