import hashlib
import hmac


def calculate_hmac(ciphertext, secret_key):
    hmac_value = hmac.new(secret_key.encode(), ciphertext, hashlib.sha256).hexdigest()
    return hmac_value