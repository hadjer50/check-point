from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Example Usage:
key = generate_key()
user_input = input("Enter a message to encrypt: ")

encrypted_message = encrypt_message(user_input, key)
print(f"Encrypted Message: {encrypted_message}")

decrypted_message = decrypt_message(encrypted_message, key)
print(f"Decrypted Message: {decrypted_message}")
