import json
import bcrypt

# CONSTANTS
DATABASE_PATH = 'database.json'


def password_hashing(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    return hashed_password.decode('utf-8')


def password_checking(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_database():
    empty_database = {
        "id": None,
        "username": None,
        "password": None,
    }

    with open(DATABASE_PATH, 'w') as f:
        json.dump(empty_database, f)


def add_user(username, user_id, password):
    hashed_password = password_hashing(password)

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


def check_if_user_exists(username):
    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    for user in database:
        if user['username'] == username:
            return True

    return False