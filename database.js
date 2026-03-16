require('dotenv').config();
const mysql = require('mysql2/promise');

let db;

async function connectDB(retries = 5, delay = 3000) {
  // Log all DB config on startup (mask password)
  console.log(`🔌  DB config → host=${process.env.DB_HOST} port=${process.env.DB_PORT} user=${process.env.DB_USER} db=${process.env.DB_NAME}`);

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      db = await mysql.createPool({
        host:     process.env.DB_HOST || 'localhost',
        port:     parseInt(process.env.DB_PORT) || 3306,
        user:     process.env.DB_USER || 'root',
        password: process.env.DB_PASS || '',
        database: process.env.DB_NAME || 'evoting',
        waitForConnections: true,
        connectionLimit: 10,
        connectTimeout: 10000,
        timezone: '+01:00'
      });

      // Force WAT on every connection
      db.pool.on('connection', conn => conn.query("SET time_zone = '+01:00'"));

      await db.query('SELECT 1');
      console.log('✅  MySQL connected');
      await createTables();
      return;
    } catch (err) {
      console.error(`❌  MySQL connection failed (attempt ${attempt}/${retries}): ${err.message || JSON.stringify(err)}`);
      console.error(`    code=${err.code} errno=${err.errno} host=${process.env.DB_HOST} port=${process.env.DB_PORT}`);
      if (attempt < retries) {
        console.log(`⏳  Retrying in ${delay/1000}s...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        process.exit(1);
      }
    }
  }
}

async function createTables() {
  const tables = [

    /* ── USERS ── */
    `CREATE TABLE IF NOT EXISTS users (
      id                         VARCHAR(36)  PRIMARY KEY,
      full_name                  VARCHAR(150) NOT NULL,
      email                      VARCHAR(150) NOT NULL UNIQUE,
      voter_id                   VARCHAR(50)  UNIQUE,
      password_hash              VARCHAR(255) NOT NULL,
      role                       ENUM('voter','admin','observer') DEFAULT 'voter',
      is_active                  TINYINT(1)   DEFAULT 1,
      is_verified                TINYINT(1)   DEFAULT 0,
      public_key                 TEXT,
      login_attempts             INT          DEFAULT 0,
      locked_until               DATETIME,
      last_login                 DATETIME,
      verification_token         VARCHAR(36),
      verification_token_expiry  DATETIME,
      created_at                 DATETIME     DEFAULT CURRENT_TIMESTAMP
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

    /* ── VOTES ── receipt_data stores the JSON receipt for verification */
    `CREATE TABLE IF NOT EXISTS votes (
      id             VARCHAR(36)  PRIMARY KEY,
      election_id    VARCHAR(36)  NOT NULL,
      anonymous_id   VARCHAR(64)  NOT NULL,
      encrypted_vote TEXT         NOT NULL,
      vote_iv        VARCHAR(64)  NOT NULL,
      vote_tag       VARCHAR(64)  NOT NULL,
      vote_hash      VARCHAR(64)  NOT NULL,
      receipt_hash   VARCHAR(64)  NOT NULL,
      receipt_sig    TEXT         NOT NULL,
      receipt_data   TEXT,
      cast_at        DATETIME     DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_vote (election_id, anonymous_id),
      FOREIGN KEY (election_id) REFERENCES elections(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── VOTE REGISTRY (who voted — separated from vote content) ── */
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

    /* ── PASSWORD RESET TOKENS ── */
    `CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         VARCHAR(36)  PRIMARY KEY,
      user_id    VARCHAR(36)  NOT NULL,
      token      VARCHAR(36)  NOT NULL UNIQUE,
      expires_at DATETIME     NOT NULL,
      used       TINYINT(1)   DEFAULT 0,
      created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

    /* ── VOTER ID RESET REQUESTS ── */
    `CREATE TABLE IF NOT EXISTS voter_id_reset_requests (
      id            VARCHAR(36)  PRIMARY KEY,
      user_id       VARCHAR(36)  NOT NULL,
      reason        TEXT,
      status        ENUM('pending','approved','rejected') DEFAULT 'pending',
      reviewed_by   VARCHAR(36),
      reject_reason TEXT,
      created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
      reviewed_at   DATETIME,
      FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (reviewed_by) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  ];

  for (const sql of tables) await db.query(sql);

  // Migrate: add receipt_data column if it doesn't exist (for existing installs)
  try {
    await db.query('ALTER TABLE votes ADD COLUMN receipt_data TEXT AFTER receipt_sig');
    console.log('✅  Migrated: added receipt_data column to votes');
  } catch (e) {
    if (e.code !== 'ER_DUP_FIELDNAME') console.error('Migration warning:', e.message);
  }

  console.log('✅  All tables ready');
}

const q  = (sql, p = []) => db.query(sql, p);
const q1 = async (sql, p = []) => { const [r] = await db.query(sql, p); return r[0] || null; };
const qa = async (sql, p = []) => { const [r] = await db.query(sql, p); return r; };

module.exports = { connectDB, q, q1, qa };
