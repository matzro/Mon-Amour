import random
import hashlib
import time

def main():
    print("Welcome to Mon-Amour <3")
    generateHash("password")    

def getQuestion():
    question = input("Insira a pergunta:")
    return question
    
def getAnswer():
    answer = input("Qual é a resposta à pergunta? ").lower()
    return answer

def randomNum():
    return random.getrandbits(128)

def getMessage():
    message = input("Digite a mensagem a ser cifrada: ")
    return message

def generateHash(password):
    key = f"{password}{randomNum()}"
    start_time = time.time()
    num_iteracoes = 0
    hash = 0
    
    # Calculate SHA256 value
    while time.time() - start_time <= 1 :
        if num_iteracoes == 0:
            hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
            num_iteracoes += 1
        hash = hashlib.sha256(hash.encode('utf-8')).hexdigest()
        num_iteracoes += 1
    print(hash)
    print(num_iteracoes)


if __name__ == "__main__":
    main()