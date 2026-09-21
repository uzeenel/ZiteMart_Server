const crypto = require('crypto');
const fs = require('fs');

const publicKey = fs.readFileSync('license_public.pem', 'utf8');
const license = fs.readFileSync('license.key', 'utf8').trim();

const [payloadB64, signature] = license.split('.');
if (!payloadB64 || !signature) {
  console.error('Malformed license');
  process.exit(1);
}

const payload = Buffer.from(payloadB64, 'base64').toString('utf8');
const isValid = crypto.verify(
  'sha256',
  Buffer.from(payload),
  publicKey,
  Buffer.from(signature, 'base64')
);

console.log('Payload:', payload);
console.log('Signature valid?', isValid);
