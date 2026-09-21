require('dotenv').config();
const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3306
});

connection.connect((err) => {
    if (err) {
        console.log('Error:', err.message);
    } else {
        console.log('Connected successfully!');
        connection.end();
    }
});