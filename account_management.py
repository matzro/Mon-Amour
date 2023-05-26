import os

from hash_functions import short_hash


HASHING_ITERATIONS = 50_000
USERDATA_PATH = "./user_data/"


def check_if_keys_exist(username: str) -> bool:
    """Checks if the user's keys already exist in the project files.

    Args:
        username (str): Username of the user to identify the keys.

    Returns:
        bool: True if the keys exist, False if not.
    """
    user_id: str = short_hash(username)

    public_key_path: str = f"{USERDATA_PATH}{user_id}/public_key_{user_id}.pem"
    private_key_path: str = f"{USERDATA_PATH}{user_id}/private_key_{user_id}.pem.aes"

    if os.path.exists(public_key_path) and os.path.exists(private_key_path):
        return True
    else:
        return False


def store_user_keys(username: str, public_key: bytes, private_key: bytes) -> None:
    """Writes the user's RSA keys to the project files.

    Args:
        username (str): Username of the keys' user.
        public_key (bytes): Public key object.
        private_key (bytes): Private key object.
    """
    user_id: str = short_hash(username)
    path: str = USERDATA_PATH + user_id + "/"

    if not os.path.exists(path):
        os.makedirs(path)

    with open(f"{path}public_key_{user_id}.pem", "wb") as f:
        f.write(public_key)
        f.close()
    
    with open(f"{path}private_key_{user_id}.pem.aes", "wb") as f:
        f.write(private_key)
        f.close()


def get_public_key_path(username: str) -> str:
    """Retrieves the path to the user's public key.

    Args:
        username (str): Username of public key's user.

    Returns:
        str: Path to the user's public key in the project files.
    """
    user_id: str = short_hash(username)
    path: str = USERDATA_PATH + user_id + "/"

    public_key_path: str = f"{path}public_key_{user_id}.pem"

    return public_key_path


def get_private_key_path(username: str) -> str:
    """Retrieves the path to the user's private key.

    Args:
        username (str): Username of private key's user.

    Returns:
        str: Path to the user's private key in the project files.
    """
    user_id: str = short_hash(username)
    path: str = USERDATA_PATH + user_id + "/"

    private_key_path: str = f"{path}private_key_{user_id}.pem.aes"

    return private_key_path
