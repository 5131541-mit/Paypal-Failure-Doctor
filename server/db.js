import pg from 'pg';

const { Pool } = pg;
export const databaseConfigured = Boolean(process.env.DATABASE_URL);
export const pool = databaseConfigured
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      max: Number(process.env.PG_POOL_MAX || 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : undefined,
    })
  : null;

if (pool) pool.on('error', (error) => console.error('PostgreSQL idle client error:', error.message));
