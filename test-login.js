const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

async function testLogin() {
    const pool = mysql.createPool({
        host: 'localhost',
        user: 'root',
        password: 'your_password',
        database: 'pos_system'
    });
    
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', ['nelson']);
    console.log('User found:', users.length);
    if (users.length > 0) {
        const user = users[0];
        console.log('Username:', user.username);
        console.log('Stored hash:', user.password);
        const isValid = await bcrypt.compare('2312Fascon????', user.password);
        console.log('Password valid:', isValid);
    }
    await pool.end();
}

testLogin();