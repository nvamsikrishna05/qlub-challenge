from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


def encrypt(message: str, key_file_name: str):
    """Encrypts a message using RSA Encryption

    Args:
        message (str): Data to be encrypted
        key_file_name (str): Public Key File Name to be used for encryption
    """
    with open(key_file_name, "rb") as file:
        public_key = RSA.importKey(file.read())

    rsa = PKCS1_OAEP.new(public_key)
    encrypted_text = rsa.encrypt(message.encode())
    return binascii.hexlify(encrypted_text).decode()


def decrypt(message: str, key_file_name: str):
    """Decrypts a message using RSA ENcryption

    Args:
        message (str): Data to be decrypted
        key_file_name (str): Private Key File Name to be used for Decryption
    """
    message = binascii.unhexlify(message.encode())
    with open(key_file_name, "rb") as file:
        private_key = RSA.importKey(file.read())

    rsa = PKCS1_OAEP.new(private_key)
    decrypted_text = rsa.decrypt(message)
    return decrypted_text.decode()


def generate_keys(bits=4096):
    """Genrates Public and Private Key Pairs for RSA Encryption and saves to the disk.
    Files are saved to the disk with name - key_rsa and key_rsa.pub

    Args:
        bits (int, optional): RSA Key bits length. Defaults to 4096.
    """
    working_directory = Path.cwd()
    keypair = RSA.generate(bits)

    private_key_file = working_directory / "key_rsa"
    with open(private_key_file, "wb") as file:
        file.write(keypair.export_key())

    public_key_file = working_directory / "key_rsa.pub"
    with open(public_key_file, "wb") as file:
        file.write(keypair.publickey().export_key())


# message = "This is Vamsi Krishna New"
# result = encrypt(message, "key_rsa.pub")
# print(f"Encrypted Text - ")
# print(result)
# print(f"Decrypted Text - ")
# result = decrypt(result, "key_rsa")
# print(result)
