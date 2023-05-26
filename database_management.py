import json

import bcrypt

import hash_functions as hf


DATABASE_PATH = 'database.json'


def password_hashing(password: str) -> bytes:
    """Hashes the user's password using the bcrypt algorithm to securely store in the database.

    This method of storing passwords prevents the database from being compromised and the passwords being exposed in plaintext.
    Storing encrypted passwords is also not recommended, as the encryption key would have to be stored in the same database.
    Hashing the passwords is the most secure way of storing them, as it is a one-way function, in other words, it is not possible to reverse the hashing process.
    Bcrypt algorithm also adds a salt to the password, which makes it even more secure.

    Args:
        password (str): Account's password in plain text.

    Returns:
        bytes: Hashed password.
    """
    hashed_password: bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    return hashed_password


def password_checking(password: str, hashed_password: bytes) -> bool:
    """Checks if the login password is correct.

    When the user logs in, the password inputed by the user is hashed and compared to the hashed password previously stored in the database.

    Args:
        password (str): Passowrd inputed by the user in plain text.
        hashed_password (bytes): Hashed password of the same user stored in the database.

    Returns:
        bool: True if the password is correct, False if not.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def load_database() -> None:
    """Loads the database from the database.json file. If the database JSON file does not exist, creates an empty one.
    """
    try:
        with open(DATABASE_PATH, 'r') as f:
            database = json.load(f)

    except FileNotFoundError:
        empty_database = []

        with open(DATABASE_PATH, 'w') as f:
            json.dump(empty_database, f)


def add_user(username: str, password: str) -> None:
    """Adds a new account to the database.

    The account is added to the database in the form of a dictionary, with the following keys being `id`, `username` and `password`.
    The password is store as a hash, using the bcrypt algorithm.

    Args:
        username (str): Username of the new account.
        password (str): Password of the new account in plain text.
    """
    user_id: str = hf.short_hash(username)
    hashed_password: str = password_hashing(password).decode('utf-8')

    new_user = {
        "id": user_id,
        "username": username,
        "password": hashed_password,
    }

    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    database.append(new_user)

    with open(DATABASE_PATH, 'w') as f:
        json.dump(database, f)


def check_if_user_exists(username: str) -> bool:
    """Checks if the user already exists in the database through a username search.

    Args:
        username (str): Account's username.

    Returns:
        bool: True if the user exists, False if not.
    """
    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    for user in database:
        if user.get('username') == username:
            return True

    return False


def get_user_password(username: str):
    """Gets the user's password from the database.

    Args:
        username (str): Account's username.

    Returns:
        The user's hashed password in bytes if the user exists, False if not.
    """
    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    for user in database:
        if user.get('username') == username:
            return user.get('password').encode('utf-8')

    return False


def get_username_by_id(user_id: str):
    """Gets the username from the database through a user ID search.

    Args:
        user_id (str): Account's ID.

    Returns:
        The user's username if the user exists, False if not.
    """
    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    for user in database:
        if user.get('id') == user_id:
            return user.get('username')
        
    return False