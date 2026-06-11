const crypto = require('crypto');

// ruleid: js-hardcoded-crypto-key
const cipher = crypto.createCipheriv('aes-256-cbc', 'hardcoded-secret-key-32byteslong!!', iv);

// ruleid: js-hardcoded-crypto-key
const hmac = crypto.createHmac('sha256', 'my-secret-key');

// ok: js-hardcoded-crypto-key
const safeKey = process.env.ENCRYPTION_KEY;
const safeCipher = crypto.createCipheriv('aes-256-cbc', safeKey, iv);

// ok: js-hardcoded-crypto-key
const keyFromConfig = config.get('encryptionKey');
const safeCipher2 = crypto.createCipheriv('aes-256-cbc', keyFromConfig, iv);
