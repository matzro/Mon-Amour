import secrets
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def main():
    print("Welcome to Mon-Amour <3")
    #generateHash("password")
    encryptMessage("Hello World!")


def getQuestion():
    question = input("Insira a pergunta:")
    return question


def getAnswer():
    answer = input("Qual é a resposta à pergunta? ").lower()
    return answer


def randomNum():
    return secrets.randbits(128)

def getMessage():
    message = input("Digite a mensagem a ser cifrada: ")
    return message

def generateHash(password):
    key = ''.join([password, str(randomNum())])
    start_time = time.time()
    num_iteracoes = 0
    hash = 0

    # Calculate SHA256 value
    while time.time() - start_time <= 1:
        if num_iteracoes == 0:
            hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
            num_iteracoes += 1
        hash = hashlib.sha256(hash.encode('utf-8')).hexdigest()
        num_iteracoes += 1
    return hash

# https://onboardbase.com/blog/aes-encryption-decryption/
def encryptMessage(message):
    key = generateHash("password")
    cipher = AES.new(key, AES.MODE_EAX) # Criar um objeto AES com a chave
    ciphertext, tag = cipher.encrypt_and_digest(message) # Cifra a mensagem e gera uma tag de autenticação
    # nonce = cipher.nonce
    return ciphertext



if __name__ == "__main__":
    main()