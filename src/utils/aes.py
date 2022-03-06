import binascii
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def generate_key():
    """Returns a Key for using against AES Encryption.
    Key is Hexified and returned
    """
    key = get_random_bytes(32)
    return binascii.hexlify(key).decode()


def encrypt(message: str, key: str):
    """Encrypts a message using AES Encryption - CFB Mode

    Args:
        message (str): message to be encrypted
        key (str): key
    """
    byte_key = binascii.unhexlify(key.encode())
    aes = AES.new(byte_key, AES.MODE_CFB)
    encrypted_text = aes.encrypt(message.encode())
    return (
        binascii.hexlify(encrypted_text).decode(),
        binascii.hexlify(aes.iv).decode(),
    )


def decrypt(message: str, key: str, iv: str):
    """Decrypts a message using AES Encryption - CFB Mode

    Args:
        message (str): message to be encrypted
        key (str): key
    """
    byte_key = binascii.unhexlify(key.encode())
    message = binascii.unhexlify(message.encode())
    iv = binascii.unhexlify(iv.encode())
    aes = AES.new(byte_key, AES.MODE_CFB, iv=iv)
    decrypted_text = aes.decrypt(message)
    return decrypted_text.decode()


# message = "This is Vamsi Krishna New"
# key = generate_key()
# result = encrypt(message, key)
# print(f"Encrypted Text - ")
# print(result)
# print(f"Decrypted Text - ")
# result = decrypt(result[0], key, result[1])
# print(result)
