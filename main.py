import hashlib
import time
import hmac
# https://www.pycryptodome.org/
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits

def main():
    print("Welcome to Mon-Amour messaging app")
    question = "A resposta e password"
    message = "Adoro as tuas batatas fritas"
    password = "password"

    hmac_value = hmac_sender(message, password.encode("utf-8"))

    iter_counter, salt, ciphertext_iv = encrypt_message(message)
    write_file(iter_counter, question, salt, ciphertext_iv, hmac_value)

    decrypted_message, hmac_received = decrypt_message("password", "ciphertext.txt")

    if hmac_receiver(decrypted_message, password.encode("utf-8"), hmac_received):
        print("HMAC is valid")
    else:
        print("HMAC is invalid")


def generate_salt():
    return get_random_bytes(BLOCK_SIZE)


# https://stackoverflow.com/questions/3566176/salting-passwords-101
def generate_hash(password):
    password_bytes = password.encode('utf-8')
    salt = generate_salt()
    key = b''.join([password_bytes, salt])
    hash_value = b''

    start_time = time.time()
    iter_counter = 0

    # Calculate SHA256 value
    while time.time() - start_time <= 1:
        if iter_counter == 0:
            hash_value = hashlib.sha256(key).digest()
            iter_counter += 1
        hash_value = hashlib.sha256(hash_value).digest()
        iter_counter += 1
    return iter_counter, salt, hash_value


def find_hash(iter_counter, salt, password):
    i = 0
    key = b''.join([password.encode('utf-8'), salt])
    hash_value = b''

    while i < iter_counter:
        if i == 0:
            hash_value = hashlib.sha256(key).digest()
            i += 1
        hash_value = hashlib.sha256(hash_value).digest()
        i += 1
    return hash_value


def hmac_sender(message, secret_key):
    hmac_value = hmac.new(secret_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    return hmac_value


def hmac_receiver(message, secret_key, hmac_value):
    new_hmac_value = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
    print(f"New HMAC value: {new_hmac_value}")
    if new_hmac_value == hmac_value.hex():
        return True
    else:
        return False


# https://onboardbase.com/blog/aes-encryption-decryption/
def encrypt_message(message):
    iter_counter, salt, key = generate_hash("password")
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))  # Cifra a mensagem
    ciphertext_iv = iv + ciphertext
    return iter_counter, salt, ciphertext_iv


def decrypt_message(password, filename):
    input = read_file(filename)
    print(f"--- File properties ---")
    print(f"Value: {input[3]}")
    iter_counter = int(input[0])
    salt = bytes.fromhex(input[2])
    key = find_hash(iter_counter, salt, password)
    hmac_received = bytes.fromhex(input[3])[:32]
    print(f"--- HMAC properties ---")
    print(f"Type: {type(hmac_received)}\nLength: {len(hmac_received)}\nValue: {hmac_received.hex()}")
    iv = bytes.fromhex(input[3])[32: 32 + 16]
    print(f"--- IV properties ---")
    print(f"Type: {type(iv)}\nLength: {len(iv)}\nValue: {iv.hex()}")
    ciphertext = bytes.fromhex(input[3])[32 + 16:]
    print(f"--- Ciphertext properties ---")
    print(f"Type: {type(ciphertext)}\nLength: {len(ciphertext)}\nValue: {ciphertext.hex()}")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_msg = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    print(f"--- Decrypted message ---")
    print(f"Value: {decrypted_msg.decode('utf-8')}")
    return decrypted_msg, hmac_received


# Writes the ciphertext to a file
# Format: no. hash iterations | question | random number | ciphertext
def write_file(iter_counter, question, salt, ciphertext, hmac_value):
    creation_time = time.time()
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()

def read_file(filename):
    with open(filename, 'r') as file:
        input = file.read().split(' | ')
        return input


if __name__ == "__main__":
    main()