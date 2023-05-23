import hashlib
import hmac


def calculate_hmac(ciphertext, secret_key):
    """This function calculates the HMAC of the ciphertext, using the secret key.
    :param ciphertext: Message encrypted with AES
    :param secret_key: Secret key used to encrypt the message
    :return: hmac_value
    """
    hmac_value = hmac.new(secret_key.encode(), ciphertext, hashlib.sha256).hexdigest()
    return hmac_value
