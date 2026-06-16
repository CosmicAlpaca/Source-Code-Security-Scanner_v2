const crypto = require('crypto');

// ruleid: js-weak-hash-algorithm
const hash1 = crypto.createHash('md5');

// ruleid: js-weak-hash-algorithm
const hash2 = crypto.createHash('sha1');

// ruleid: js-weak-hash-algorithm
const hash3 = crypto.createHash('MD5');

// ok: js-weak-hash-algorithm
const safeHash = crypto.createHash('sha256');

// ok: js-weak-hash-algorithm
const safeHash2 = crypto.createHash('sha512');
