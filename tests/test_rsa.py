
from crypto import RSAHandler

rsa = RSAHandler()

# Generate keys
private_key, public_key = rsa.generate_key_pair()

message = b"SecureTrans Test Message"

# Encrypt
encrypted = rsa.encrypt(public_key, message)
print("Encrypted:", encrypted)

# Decrypt
decrypted = rsa.decrypt(private_key, encrypted)
print("Decrypted:", decrypted)