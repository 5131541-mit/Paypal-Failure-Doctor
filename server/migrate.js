import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { pool } from './db.js';

if (!pool) {
  console.error('DATABASE_URL is required to run database migrations.');
  process.exitCode = 1;
} else {
  try {
    const schema = await readFile(fileURLToPath(new URL('./schema.sql', import.meta.url)), 'utf8');
    await pool.query(schema);
    console.log('Database schema is up to date.');
  } catch (error) {
    console.error('Database migration failed:', error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
