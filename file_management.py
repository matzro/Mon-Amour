from Crypto.PublicKey import RSA
import account_management as am
import hash_functions as hf
import glob
import os

MESSAGE_PATH = "./messages/"


# ------------- AES --------------
# ---- Writes the ciphertext to a file
def write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, addressee):
    # Format: no. hash iterations | question | random number | hmac+ciphertext | signature
    user_id = hf.short_hash(username)
    addressee_id = hf.short_hash(addressee)
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()} | {signature.hex()}"
    
    if not os.path.exists(MESSAGE_PATH):
        os.makedirs(MESSAGE_PATH)

    with open(f"{MESSAGE_PATH}{user_id}_{addressee_id}.txt", "w") as file:
        file.write(output)
        file.close()


# ---- Reads and splits the ciphertext from a file
def read_file(username):
    user_id = hf.short_hash(username)
    files = glob.glob(f"{MESSAGE_PATH}*_{user_id}.txt")
    temp = files[0].split('_')[0]
    sender_id = temp.split('\\')[1]


    print(f"File: {files[0]}")
    print(f"Message from {sender_id}")
    
    with open(files[0], 'r') as file:
        input = file.read().split(' | ')
        return input, sender_id



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