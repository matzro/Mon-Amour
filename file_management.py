# Writes the ciphertext to a file
def write_file(iter_counter, question, salt, ciphertext, hmac_value):
    # Format: no. hash iterations | question | random number | hmac+iv+ciphertext
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()}"
    with open(f"ciphertext.txt", "w") as file:
        file.write(output)
        file.close()

# Reads and splits the ciphertext from a file
def read_file(filename):
    with open(filename, 'r') as file:
        input = file.read().split(' | ')
        return input