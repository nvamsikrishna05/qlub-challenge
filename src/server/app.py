import os, sys

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

import uvicorn
from starlette.applications import Starlette
from starlette.websockets import WebSocket, WebSocketDisconnect
from starlette.responses import JSONResponse, Response
from utils.rsa import decrypt as rsa_decrypt
from utils.aes import encrypt, decrypt, generate_key

app = Starlette()


@app.route("/")
async def hello(request):
    return JSONResponse({"message": "Hello Qlub"})


@app.websocket_route("/order")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.headers["Authentication"]
    isValid = validate_token(token)
    if not isValid:
        return Response("Invalid token", status_code=401)

    aes_key = generate_key()
    headers = [("Token".encode(), aes_key.encode())]
    await websocket.accept(headers=headers)
    while True:
        try:
            data = await websocket.receive_json()
            result = parse_response(data, aes_key)
            print(f"Response - {result}")
            output = encrypt("From my Starlette Server :)", key=aes_key)
            response = {"message": output[0], "iv": output[1]}
            await websocket.send_json(response)
        except WebSocketDisconnect as ex:
            print(f"Websocket connection closed")
            break


def parse_response(response, key):
    """Decrypts the Data received from the client

    Args:
        response (json): encrypted json data from client as response

    Returns:
        json: Decrypted json data
    """
    iv = response["iv"]
    encrypted_message = response["message"]
    decrypted_message = decrypt(encrypted_message, key, iv)
    return {"message": decrypted_message}


def validate_token(token: str):
    """Validates the encrypted token

    Args:
        token (str): rsa encrypted token
    """
    # Replace magic string file name and fetch it from config
    value = rsa_decrypt(token, "key_rsa")

    # Use an actual authentication
    if value == "This is a Dummy Password":
        return True
    return False


if __name__ == "__main__":
    uvicorn.run("app:app", host="localhost", port=3000, reload=True)
