const bcrypt = require('bcrypt');
const hash = bcrypt.hashSync('2312fascon', 10);
console.log(hash);