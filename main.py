import ast
import base64
import hashlib
import time
# https://www.pycryptodome.org/
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

# GLOBAL VARIABLES
__BLOCK_SIZE__ = 16  # 128 bits

def main():
    print("Welcome to Mon-Amour <3")
    question = "A resposta e password"
    iter_counter, salt, ciphertext_iv = encryptMessage("Adoro as tuas batatas fritas")
    writeFile(iter_counter, question, salt, ciphertext_iv)
    decryptMessage("password")


def generateSalt128():
    return get_random_bytes(__BLOCK_SIZE__)


# https://stackoverflow.com/questions/3566176/salting-passwords-101
def generateHash(password):
    passwordBytes = password.encode('utf-8')
    salt = generateSalt128()
    key = b''.join([passwordBytes, salt])
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


def findHash(iter_counter, salt, password):
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
def encryptMessage(message):
    iter_counter, salt, key = generateHash("password")
    iv = get_random_bytes(__BLOCK_SIZE__)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode(), __BLOCK_SIZE__))  # Cifra a mensagem
    ciphertext_iv = iv + ciphertext
    print("cipher:")
    print(ciphertext_iv)
    return iter_counter, salt, ciphertext_iv


def decryptMessage(password):
    with open("ciphertext.txt", 'r') as file:
        input = file.read().split(' | ')
        key = findHash(int(input[0]), bytes.fromhex(input[2]), password)
        iv = bytes.fromhex(input[3])[:__BLOCK_SIZE__]
        print("decrypted:")
        print(type(iv))
        print(len(iv))
        print(iv)
        ciphertext = bytes.fromhex(input[3])[__BLOCK_SIZE__:]
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        decrypted_msg = unpad(cipher.decrypt(ciphertext), __BLOCK_SIZE__)
        print(decrypted_msg.decode('utf-8'))


# Writes the ciphertext to a file
# Format: no. hash iterations | question | random number | ciphertext
def writeFile(iter_counter, question, salt, ciphertext):
    creation_time = time.time()
    output = f"{iter_counter} | {question} | {salt.hex()} | {ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()


def getQuestion():
    question = input("Insira a pergunta:")
    return question


def getAnswer():
    answer = input("Qual é a resposta à pergunta? ").lower()
    return answer


def getMessage():
    message = input("Digite a mensagem a ser cifrada: ")
    return message

if __name__ == "__main__":
    main()