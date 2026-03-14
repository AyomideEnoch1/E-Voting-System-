/**
 * Run this file on your server: node check_time.js
 * It will print exactly what time Node.js sees vs what MySQL stores,
 * so we can find the exact offset and fix it permanently.
 */
require('dotenv').config();
const mysql = require('mysql2/promise');

async function diagnose() {
  const db = await mysql.createPool({
    host:     process.env.DB_HOST || 'localhost',
    port:     process.env.DB_PORT || 3306,
    user:     process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'evoting',
  });

  console.log('\n========================================');
  console.log('  TIMEZONE DIAGNOSTIC REPORT');
  console.log('========================================\n');

  // 1. Node.js time
  const nodeNow = new Date();
  console.log('1. Node.js new Date()         :', nodeNow.toString());
  console.log('   Node.js ISO (UTC)           :', nodeNow.toISOString());
  console.log('   Node.js local offset (hrs)  :', -nodeNow.getTimezoneOffset() / 60);

  // 2. MySQL time
  const [[mysqlTime]] = await db.query("SELECT NOW() as now, @@global.time_zone as gtz, @@session.time_zone as stz");
  console.log('\n2. MySQL NOW()                :', mysqlTime.now.toString());
  console.log('   MySQL global time_zone      :', mysqlTime.gtz);
  console.log('   MySQL session time_zone     :', mysqlTime.stz);

  // 3. What gets stored when you INSERT NOW()
  const [[inserted]] = await db.query("SELECT NOW() + 0 as raw");
  console.log('\n3. MySQL raw numeric NOW()    :', inserted.raw);

  // 4. Difference between Node and MySQL
  const mysqlMs  = new Date(mysqlTime.now).getTime();
  const diffMins = Math.round((nodeNow.getTime() - mysqlMs) / 60000);
  console.log('\n4. Difference (Node - MySQL)  :', diffMins, 'minutes');

  // 5. Show what a sample election time looks like round-tripping
  // Insert a test row and read it back
  await db.query("CREATE TABLE IF NOT EXISTS _tz_test (t DATETIME) ENGINE=InnoDB");
  await db.query("INSERT INTO _tz_test VALUES (NOW())");
  const [[testRow]] = await db.query("SELECT t, CONVERT_TZ(t, @@session.time_zone, '+01:00') as wat FROM _tz_test ORDER BY t DESC LIMIT 1");
  console.log('\n5. Stored DATETIME (as JS Date):', new Date(testRow.t).toString());
  console.log('   Same time in WAT (+01:00)   :', testRow.wat);
  await db.query("DROP TABLE _tz_test");

  console.log('\n========================================');
  console.log('  Copy and paste ALL of the above');
  console.log('  and send it back to Claude.');
  console.log('========================================\n');

  process.exit(0);
}

diagnose().catch(e => { console.error('Error:', e.message); process.exit(1); });
