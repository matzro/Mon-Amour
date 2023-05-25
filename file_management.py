import glob
import os

from Crypto.PublicKey import RSA

import account_management as am
import hash_functions as hf


MESSAGE_PATH = "./messages/"


def write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, addressee) -> None:
    """Writes the ciphertext and its attributes to a file in the messages folder. The file name is the concatenation of the sender's user ID and the receiver's user ID. The ciphertext file has the following format: `Number of hash iterations | Question | Salt | HMAC + Ciphertext | Digital Signature`.

    Args:
        iter_counter: Number of hash iterations used to generate the key.
        question: Sender's question to the receiver. The receiver must answer the question correctly in order to decrypt the message.
        salt: Salt used to generate the key.
        ciphertext: Ciphertext generated from the message's encryption.
        hmac_value: HMAC value of the ciphertext.
        signature: Digital signature of the message.
        username: Sender's username.
        addressee: Receiver's username.
    """
    user_id = hf.short_hash(username)
    addressee_id = hf.short_hash(addressee)
    output = f"{iter_counter} | {question} | {salt.hex()} | {hmac_value}{ciphertext.hex()} | {signature.hex()}"
    
    if not os.path.exists(MESSAGE_PATH):
        os.makedirs(MESSAGE_PATH)

    with open(f"{MESSAGE_PATH}{user_id}_{addressee_id}.txt", "w") as file:
        file.write(output)
        file.close()


def read_file(username: str) -> tuple[list[str], str]:
    """Reads and splits the ciphertext and its attributes from a file in the messages folder. The file name is the concatenation of the sender's user ID and the receiver's user ID. The ciphertext file has the following format: `Number of hash iterations | Question | Salt | HMAC + Ciphertext | Digital Signature`.

    Args:
        username (str): Username of the receiver.

    Returns:
        tuple[list[str], str]: A tuple containing the ciphertext's data and the sender's ID for verification of the digital signature.
    """
    user_id: str = hf.short_hash(username)
    files: list[glob.AnyStr@glob] = glob.glob(f"{MESSAGE_PATH}*_{user_id}.txt")
    temp: str = files[0].split('_')[0]
    sender_id: str = temp.split('\\')[1]

    # print(f"File: {files[0]}")
    # print(f"Message from {sender_id}")
    
    with open(files[0], 'r') as file:
        input: list[str] = file.read().split(' | ')
        return input, sender_id


def import_private_key(username: str) -> RSA.RsaKey:
    """Imports the RSA private key from a .pem file. 

    Args:
        username (str): Username associated with the private key.

    Returns:
        RSA.RsaKey: Private key object.
    """
    with open(am.get_private_key_path(username), 'rb') as f:
        private_key: RSA.RsaKey = RSA.import_key(f.read())

    return private_key


def import_public_key(username: str) -> RSA.RsaKey:
    """Imports the RSA public key from a .pem file.

    Args:
        username (str): Username associated with the public key.

    Returns:
        RSA.RsaKey: Public key object.
    """
    with open(am.get_public_key_path(username), 'rb') as f:
        public_key: RSA.RsaKey = RSA.import_key(f.read())

    return public_key