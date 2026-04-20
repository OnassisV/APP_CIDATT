import mysql from 'mysql2/promise';

let pool;

function useSsl() {
  return String(process.env.MYSQL_SSL || '').toLowerCase() === 'true'
    ? { rejectUnauthorized: false }
    : undefined;
}

export function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.MYSQLHOST,
      port: Number(process.env.MYSQLPORT || 3306),
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      ssl: useSsl()
    });
  }

  return pool;
}

export async function query(sql, params = []) {
  const currentPool = getPool();
  const [rows] = await currentPool.execute(sql, params);
  return rows;
}

export async function withTransaction(work) {
  const connection = await getPool().getConnection();

  try {
    await connection.beginTransaction();
    const result = await work(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
