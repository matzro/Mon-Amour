import hashlib
import time
# https://www.pycryptodome.org/
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# GLOBAL VARIABLES
__BLOCK_SIZE__ = 16  # 128 bits


def main():
    print("Welcome to Mon-Amour <3")
    question = "Qual é a minha flor favorita?"
    iter_counter, salt, ciphertext, iv = encryptMessage("HELLLOOOOOO")
    writeFile(iter_counter, question, salt, ciphertext)
    decryptMessage()


def getQuestion():
    question = input("Insira a pergunta:")
    return question


def getAnswer():
    answer = input("Qual é a resposta à pergunta? ").lower()
    return answer


def getMessage():
    message = input("Digite a mensagem a ser cifrada: ")
    return message


def generateSalt128():
    return get_random_bytes(128)


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


# https://onboardbase.com/blog/aes-encryption-decryption/
def encryptMessage(message):
    iter_counter, salt, key = generateHash("password")
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), __BLOCK_SIZE__))  # Cifra a mensagem

    return iter_counter, salt, ciphertext, iv


def decryptMessage():
    with open("ciphertext.txt", 'r') as file:
        input = file.read().split(' | ')
        


# Writes the ciphertext to a file
# Format: no. hash iterations | question | random number | ciphertext
def writeFile(iter_counter, question, random_num, ciphertext):
    creation_time = time.time()
    output = f"{iter_counter} | {question} | {random_num} | {ciphertext}"
    with open(f"ciphertext_{creation_time}.txt", "w") as file:
        file.write(output)
        file.close






if __name__ == "__main__":
    main()