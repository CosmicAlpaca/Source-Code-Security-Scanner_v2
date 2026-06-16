from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from cryptography.fernet import Fernet
import os

# ruleid: py-hardcoded-crypto-key
cipher = AES.new("hardcoded-key-16", AES.MODE_CBC)

# ruleid: py-hardcoded-crypto-key
f = Fernet("hardcoded-fernet-key-base64-padded==")

# ok: py-hardcoded-crypto-key
key = os.environ.get('AES_KEY').encode()
safe_cipher = AES.new(key, AES.MODE_CBC)

# ok: py-hardcoded-crypto-key
fernet_key = os.environ['FERNET_KEY']
safe_f = Fernet(fernet_key)
