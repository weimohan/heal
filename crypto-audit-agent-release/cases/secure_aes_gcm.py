from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(32)
nonce = token_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
