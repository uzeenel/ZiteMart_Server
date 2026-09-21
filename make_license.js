const crypto = require('crypto');
const fs = require('fs');

// Usage: node make_license.js YYYY-MM-DD "Client Name"
const expiry = process.argv[2];
const clientName = process.argv[3] || 'Client';

if (!expiry || !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) {
  console.error('Usage: node make_license.js YYYY-MM-DD "Client Name"');
  process.exit(1);
}

const privateKey = fs.readFileSync('license_private.pem', 'utf8');

const payload = JSON.stringify({ expiry, client: clientName });
const signature = crypto.sign('sha256', Buffer.from(payload), privateKey).toString('base64');
const license = Buffer.from(payload).toString('base64') + '.' + signature;

fs.writeFileSync('license.key', license);
console.log('license.key written for', clientName, 'expiring', expiry);
