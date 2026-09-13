import hashlib
import random
from Crypto.Cipher import DES

api_key = "sk_demo_not_real"
random.seed(42)
token = hashlib.md5(api_key.encode()).hexdigest()
cipher = DES.new(b"12345678", DES.MODE_ECB)
