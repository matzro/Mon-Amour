import hashlib
import hmac


def hmac_sender(message, secret_key):
    hmac_value = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
    return hmac_value


def hmac_receiver(message, secret_key, hmac_value):
    new_hmac_value = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
    print(f"New HMAC value: {new_hmac_value}")
    if new_hmac_value == hmac_value.hex():
        return True
    else:
        return False