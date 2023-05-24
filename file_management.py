from Crypto.PublicKey import RSA
import account_management as am


# ------------- AES --------------
# ---- Writes the ciphertext to a file
def write_file(iter_counter, question, salt, ciphertext, hmac_value):
    # Format: no. hash iterations | question | random number | hmac+ciphertext
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()


# ---- Reads and splits the ciphertext from a file
def read_file(filename):
    with open(filename, 'r') as file:
        input = file.read().split(' | ')
        return input


# ------------- RSA --------------
# ---- Opens the private key
def import_private_key(username):
    # Deserialize the PEM file to a private key object
    with open(am.get_private_key_path(username), 'rb') as f:
        private_key = RSA.import_key(f.read())

    return private_key


# ---- Opens the public key
def import_public_key(username):
    # Deserialize the PEM file to a public key object
    with open(am.get_public_key_path(username), 'rb') as f:
        public_key = RSA.import_key(f.read())

    return public_key


# ---- Writes the ciphered secret key to a file (maybe not needed)
def write_rsa_cipher(encrypted_secret_key, username):
    with open(f"rsa_ciphertext_{username}.txt", 'w') as file:
        file.write(encrypted_secret_key.hex())
        file.close()


# ---- Reads ciphered secret key from the file (maybe not needed)
def read_rsa_cipher(username):
    with open(f"rsa_ciphertext_{username}.txt", 'r') as file:
        ciphertext = bytes.fromhex(file.read())
        return ciphertext


# ---- Writes the deciphered secret key to a file (maybe not needed)
def write_rsa_decipher(deciphered_secretkey, username):
    with open(f"deciphered_key_{username}.txt", 'w') as file:
        file.write(deciphered_secretkey)
        file.close()


# ------- DIGITAL SIGNATURE -------
# ---- Writes the signature to a file
def write_signature(signature):
    with open(f"signature.txt", 'w') as file:
        file.write(signature.hex())
        file.close()


# ---- Reads the signature from a file
def read_signature():
    with open(f"signature.txt", 'r') as file:
        input = bytes.fromhex(file.read())
        return input
