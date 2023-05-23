import json
import bcrypt

# CONSTANTS
DATABASE_PATH = 'database.json'


# Hashes the password inserted by the user
def password_hashing(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    return hashed_password.decode('utf-8')


# Checks if the password inserted by the user is the same as the one in the database
def password_checking(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# Creates an empty JSON database
def create_database():
    empty_database = {
        "id": None,
        "username": None,
        "password": None,
    }

    with open(DATABASE_PATH, 'w') as f:
        json.dump(empty_database, f)


# Adds a new user to the database
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


# Checks if the user already exists in the database
def check_if_user_exists(username):
    with open(DATABASE_PATH, 'r') as f:
        database = json.load(f)

    for user in database:
        if user['username'] == username:
            return True

    return False