import hashlib
import hmac

def calculate_hmac(ciphertext: bytes, secret_key: str) -> str:
    """Calculates the HMAC value of the ciphertext and secret key using the SHA256 algorithm

    Args:
        ciphertext (bytes): Ciphertext to be authenticated.
        secret_key (str): Secret key to authenticate the ciphertext.

    Returns:
        str: The ciphertext's HMAC value.
    """
    hmac_value = hmac.new(secret_key.encode(), ciphertext, hashlib.sha256).hexdigest()
    
    return hmac_value