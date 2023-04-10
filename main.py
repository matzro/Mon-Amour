import hashlib
import time
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
    iter_counter, salt, ciphertext_iv = encrypt_message("Adoro as tuas batatas fritas")
    write_file(iter_counter, question, salt, ciphertext_iv)
    decrypt_message("password")


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


# https://onboardbase.com/blog/aes-encryption-decryption/
def encrypt_message(message):
    iter_counter, salt, key = generate_hash("password")
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))  # Cifra a mensagem
    ciphertext_iv = iv + ciphertext
    print("--- Ciphertext ---")
    print(f"Value: {ciphertext_iv}")
    print(f"-----------------")
    return iter_counter, salt, ciphertext_iv


def decrypt_message(password):
    with open("ciphertext.txt", 'r') as file:
        input = file.read().split(' | ')
        key = find_hash(int(input[0]), bytes.fromhex(input[2]), password)
        iv = bytes.fromhex(input[3])[:BLOCK_SIZE]
        print(f"--- Decrypted properties ---")
        print(f"Type: {type(iv)}\nLength: {len(iv)}\nValue: {iv}")
        print(f"----------------------------")
        ciphertext = bytes.fromhex(input[3])[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        decrypted_msg = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        print(f"--- Decrypted message ---")
        print(f"Value: {decrypted_msg.decode('utf-8')}")


# Writes the ciphertext to a file
# Format: no. hash iterations | question | random number | ciphertext
def write_file(iter_counter, question, salt, ciphertext):
    creation_time = time.time()
    output = f"{iter_counter} | {question} | {salt.hex()} | {ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()


if __name__ == "__main__":
    main()