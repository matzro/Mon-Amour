def print_login():
    print("\n")
    print("Enter your login credentials")
    print("\n")

def print_menu():
    print("\n")
    print("Welcome to Mon-Amour messaging app")
    print("1. Send message")
    print("2. Receive message")
    print("------------------")
    print("9. Help")
    print("0. Exit")
    print("\n")


def print_properties(input, hmac_received, ciphertext, decrypted_msg):

    print(f"--- HMAC+Ciphertext ---")
    print(f"Value: {input[3]}")
    print(f"--- HMAC properties ---")
    print(f"Type: {type(hmac_received)}\nLength: {len(hmac_received)}\nValue: {hmac_received.hex()}")
    print(f"--- Ciphertext properties ---")
    print(f"Type: {type(ciphertext)}\nLength: {len(ciphertext)}\nValue: {ciphertext.hex()}")
    print(f"--- Decrypted message ---")
    print(f"Value: {decrypted_msg.decode('utf-8')}")