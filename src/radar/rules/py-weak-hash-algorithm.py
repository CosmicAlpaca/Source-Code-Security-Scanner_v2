import hashlib

# ruleid: py-weak-hash-algorithm
h1 = hashlib.md5(data)

# ruleid: py-weak-hash-algorithm
h2 = hashlib.sha1(data)

# ruleid: py-weak-hash-algorithm
h3 = hashlib.md5()
h3.update(data)

# ok: py-weak-hash-algorithm
safe1 = hashlib.sha256(data)

# ok: py-weak-hash-algorithm
safe2 = hashlib.sha3_256(data)

# ok: py-weak-hash-algorithm
safe3 = hashlib.blake2b(data)
