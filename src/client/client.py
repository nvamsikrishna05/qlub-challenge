import os, sys

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

import asyncio
import websockets
from websockets.exceptions import ConnectionClosedError
import json
from utils.rsa import encrypt as rsa_encrypt
from utils.aes import encrypt, decrypt, generate_key

# Use config instead of magic strings
password = "This is a Dummy Password"
rsa_key = "key_rsa.pub"

url = "ws://localhost:3000/order"


async def start_ws():
    headers = {"Authentication": rsa_encrypt(password, rsa_key)}
    async with websockets.connect(url, extra_headers=headers) as ws:
        key = ws.response_headers["Token"]
        while True:
            try:
                await ws.send(prepare_data("Hello from Qlub", key))
                response = await ws.recv()
                data = parse_response(response, key)
                print(data)
                await asyncio.sleep(5)
            except ConnectionClosedError:
                print(f"Websocket connection closed")
                break


def parse_response(response, key):
    """Decrypts the Data received from the server

    Args:
        response (json): encrypted json data from server as response

    Returns:
        json: Decrypted json data
    """
    response = json.loads(response)
    iv = response["iv"]
    encrypted_message = response["message"]
    decrypted_message = decrypt(encrypted_message, key, iv)
    return {"message": decrypted_message}


def prepare_data(message, key):
    """Encrypts the Data for Sending using AES

    Args:
        message (_type_): Message to be sent
        key (_type_): Key to use for encryption

    Returns:
        json : json data can be sent for server
    """
    output = encrypt(message, key)
    return json.dumps({"message": output[0], "iv": output[1]})


asyncio.run(start_ws())
