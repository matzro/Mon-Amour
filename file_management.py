from Crypto.PublicKey import RSA
import account_management as am
import hash_functions as hf
import glob


# ------------- AES --------------
# ---- Writes the ciphertext to a file
def write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, addressee):
    # Format: no. hash iterations | question | random number | hmac+ciphertext | signature
    user_id = hf.short_hash(username)
    addressee_id = hf.short_hash(addressee)
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()} | {signature.hex()}"
    with open(f"{user_id}_{addressee_id}.txt", "w") as file:
        file.write(output)
        file.close()


# ---- Reads and splits the ciphertext from a file
def read_file(username):
    user_id = hf.short_hash(username)
    files = glob.glob(f"*_{user_id}.txt")
    sender_id = files[0].split('_')[0]

    print(f"File: {files[0]}")
    print(f"Message from {sender_id}.")
    
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