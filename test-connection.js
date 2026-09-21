const mysql = require('mysql2/promise');

async function test() {
    try {
        const conn = await mysql.createConnection({
            host: '172.125.0.200',
            user: 'root',
            password: '2312Fascon????',
            database: 'pos_system'
        });
        console.log('✅ Database connected successfully!');
        const [rows] = await conn.query('SELECT COUNT(*) as count FROM products');
        console.log('Products count:', rows[0].count);
        await conn.end();
    } catch (err) {
        console.error('❌ Connection failed:', err.message);
    }
}
test();