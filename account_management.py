import os
from hash_functions import short_hash

# Constants
USERDATA_PATH = "./user_data/"
HASHING_ITERATIONS = 50_000


def check_if_keys_exist(username):
    user_id = short_hash(username)

    public_key_path = f"{USERDATA_PATH}{user_id}/public_key_{user_id}.pem"
    private_key_path = f"{USERDATA_PATH}{user_id}/private_key_{user_id}.pem"

    if os.path.exists(public_key_path) and os.path.exists(private_key_path):
        return True
    else:
        return False


def store_user_keys(username, public_key, private_key):
    user_id = short_hash(username)
    path = USERDATA_PATH + user_id + "/"

    if not os.path.exists(path):
        os.makedirs(path)

    with open(f"{path}public_key_{user_id}.pem", "wb") as f:
        f.write(public_key)
        f.close()
    
    with open(f"{path}private_key_{user_id}.pem", "wb") as f:
        f.write(private_key)
        f.close()


def get_keys_path(username):
    user_id = short_hash(username)
    path = USERDATA_PATH + user_id + "/"

    public_key_path = f"{path}public_key_{user_id}.pem"
    private_key_path = f"{path}private_key_{user_id}.pem"

    return public_key_path, private_key_path