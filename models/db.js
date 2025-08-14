const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false, // Required for Render PostgreSQL
  },
});

pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected error on idle PostgreSQL client', err);
  process.exit(-1);
});

// Test the connection immediately
(async () => {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('DB connected:', res.rows);
  } catch (err) {
    console.error('DB connection error:', err);
  }
})();

module.exports = pool;
