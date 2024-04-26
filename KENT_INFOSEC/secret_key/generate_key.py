from cryptography.fernet import Fernet

def generate_and_save_key():
    key = Fernet.generate_key()
    with open("../path_to_key.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved successfully.")

if __name__ == "__main__":
    generate_and_save_key()