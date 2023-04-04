import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def main():
    print("Welcome to Mon-Amour <3")
    # generateHash("password")
    print(encryptMessage("HELLLOOOOOO"))


def getQuestion():
    question = input("Insira a pergunta:")
    return question


def getAnswer():
    answer = input("Qual é a resposta à pergunta? ").lower()
    return answer


def generateSalt128():
    return get_random_bytes(128)


def getMessage():
    message = input("Digite a mensagem a ser cifrada: ")
    return message


# https://stackoverflow.com/questions/3566176/salting-passwords-101
def generateHash(password):
    passwordBytes = password.encode('utf-8')
    salt = generateSalt128()
    key = b''.join([passwordBytes, salt])
    start_time = time.time()
    num_iteracoes = 0
    hash_value = b''

    # Calculate SHA256 value
    while time.time() - start_time <= 1:
        if num_iteracoes == 0:
            hash_value = hashlib.sha256(key).digest()
            num_iteracoes += 1
        hash_value = hashlib.sha256(hash_value).digest()
        num_iteracoes += 1
    return hash_value


# https://onboardbase.com/blog/aes-encryption-decryption/
def encryptMessage(message):
    key = generateHash("password")
    cipher = AES.new(key, AES.MODE_CBC)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), 16))  # Cifra a mensagem

    return ciphertext


if __name__ == "__main__":
    main()
