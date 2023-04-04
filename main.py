import hashlib
import time
# https://www.pycryptodome.org/
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def main():
    print("Welcome to Mon-Amour <3")
    question = "Qual é a minha flor favorita?"
    iter_counter, salt, ciphertext = encryptMessage("HELLLOOOOOO")
    writeFile(iter_counter, question, salt, ciphertext)


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
    cipher = AES.new(key, AES.MODE_CBC)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), 16))  # Cifra a mensagem

    return iter_counter, salt, ciphertext


# Writes the ciphertext to a file
# Format: no. hash iterations | question | random number | ciphertext
def writeFile(iter_counter, question, random_num, ciphertext):
    output = f"{iter_counter} | {question} | {random_num} | {ciphertext}"
    with open("ciphertext.txt", "w") as file:
        file.write(output)
        file.close


if __name__ == "__main__":
    main()
