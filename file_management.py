# Writes the ciphertext to a file
from Crypto.PublicKey import RSA


def write_file(iter_counter, question, salt, ciphertext, hmac_value):
    # Format: no. hash iterations | question | random number | hmac+iv+ciphertext
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()


# Writes the private key to a file
def import_private_key(username):
    # Deserialize the PEM file to a private key object
    with open(f'private_key_{username}.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())

    return private_key


# Writes the public key to a file
def import_public_key(username):
    # Deserialize the PEM file to a public key object
    with open(f'public_key_{username}.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())

    return public_key


# Writes the ciphertext to a file
def write_rsa_cipher(encrypted_secret_key, username):
    with open(f"rsa_ciphertext_{username}.txt", 'w') as file:
        file.write(encrypted_secret_key.hex())
        file.close()

# Reads ciphertext from a file
def read_rsa_cipher(username):
    with open(f"rsa_ciphertext_{username}.txt", 'r') as file:
        input = bytes.fromhex(file.read())
        return input



# Reads and splits the ciphertext from a file
def read_file(filename):
    with open(filename, 'r') as file:
        input = file.read().split(' | ')
        return input



def write_rsa_decipher(deciphered_secretkey, username):
    with open(f"deciphered_key{username}", 'w') as file:
        file.write(deciphered_secretkey.hex())
        file.close()
