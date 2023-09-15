import hashlib
user_database = {
    'user1': {
        'password': 'e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4',
        'salt': 'salt1'
    },
    'user2': {
        'password': '5f4dcc3b5aa765d61d8327deb882cf99',
        'salt': 'salt2'
    }
}

def hash_password(password, salt):
    """Hashes the password using a salt."""
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    hashed_password = hashlib.sha1(password + salt).hexdigest()
    return hashed_password

def register():
    """Register a new user."""
    username = input("Enter username: ")
    password = input("Enter password: ")
    salt = input("Enter salt: ")

    hashed_password = hash_password(password, salt)

    user_database[username] = {
        'password': hashed_password,
        'salt': salt
    }
    print("Registration successful!")

def login():
    """Log in an existing user."""
    username = input("Enter username: ")
    password = input("Enter password: ")

    if username in user_database:
        stored_password = user_database[username]['password']
        salt = user_database[username]['salt']

        if hash_password(password, salt) == stored_password:
            print("Login successful!")
        else:
            print("Login failed. Incorrect password.")
    else:
        print("Login failed. User not found.")

if __name__ == "__main__":
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Select an option: ")

        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")
