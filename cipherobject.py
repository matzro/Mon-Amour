class CipherObject:
    message: str = None
    secret_key: str = None
    iter_counter: int = None
    salt: str = None
    hmac: str = None
    iv: str = None
    ciphertext: str = None
    
    def __init__(self, message, secret_key):
        self.message = message
        self.secret_key = secret_key

    # Setters
    def set_iter_counter(self, iter_counter):
        self.iter_counter = iter_counter

    def set_salt(self, salt):
        self.salt = salt

    def set_hmac(self, hmac):
        self.hmac = hmac

    def set_iv(self, iv):
        self.iv = iv

    def set_ciphertext(self, ciphertext):
        self.ciphertext = ciphertext

    # Getters
    def get_iter_counter(self):
        return self.iter_counter

    def get_salt(self):
        return self.salt

    def get_hmac(self):
        return self.hmac

    def get_iv(self):
        return self.iv

    def get_ciphertext(self):
        return self.ciphertext
    