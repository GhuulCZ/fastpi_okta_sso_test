import requests
import json
import logging
import base64
import random
import string
import hashlib
import os


from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import List
from multiprocessing import Process, Queue


GLOBALQ = Queue()

authorization_list = {}

index_html = """
<!DOCTYPE html>
<html>
<head>
  <title>Login Successful - Close Now</title>
</head>
<body>
  <p>SSO Complete</p>
  <h1>You can close this window now</h1>
  <!-- <button onclick="window.close()">Close Window</button> -->
</body>
</html>
"""


USERMAIL = None


class ssoConfig():

    def __init__(
        self,
        auth_uri: str,
        client_id: str,
        redirect_uri: str,
        issuer: str,
        token_uri: str,
        userinfo_uri: str
        ) -> None:
        self.auth_uri = auth_uri
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.issuer = issuer
        self.token_uri = token_uri
        self.userinfo_uri = userinfo_uri
        pass



class SSOException(Exception):
    def __init__(self, status: int = 400, message: str = "No details") -> None:
        logging.warning(f"SOO exception: {message} [{status}]")
        self.message = message
        self.status = status
        pass


def config_load(filename: str = "secret.json") -> ssoConfig:
    config = None
    with open(filename) as f:
        config = json.load(f)
    config = ssoConfig(**config)
    return config


def generate_pkce_code(size: int = 48):
    characters = string.ascii_letters + string.digits
    rand_string = "".join(
        list(random.choice(characters) for x in range(0,size))
    )
    return rand_string

def create_code_challenge(code: str):
    challenge = hashlib.sha256(code.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(challenge).decode()
    challenge = challenge.replace("=", "")
    return challenge

def generate_state_name():
    return generate_pkce_code(16)


def get_access_token(
        code: str, state: str
    ):

    verify_code = authorization_list.get(state)
    logging.debug(f"verify code: {verify_code}")
    
    if not verify_code:
        raise SSOException(
            message=f"unable to find verification code"
        )

    data = {
        "grant_type": "authorization_code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "code": code,
        "code_verifier": verify_code
    }

    logging.debug(f"request data: {data}")

    request = requests.post(
        url=config.token_uri,
        data=data,
        allow_redirects=False
    )

    logging.debug(request)
    logging.info(f"request status: {request.status_code}")
    logging.debug(f"token: {request.text}")

    if (not request.status_code == 200 or not request.json()):
        raise SSOException(message="unable to request token from Okta")

    return request.json()


def decode_token(data: str):
    token = {}
    try: 
        h, payload, sig = data.split(".")
        adjust_len = 4 - len(data)%4
        payload += "="*adjust_len
        token = base64.b64decode(payload).decode("utf-8")
        token = json.loads(token)
    except:
        raise SSOException(
            message="unable to decode token"
        )
    return token



def redirect_to_okta_login(
    config: ssoConfig,
    code_verify: str
    ):

    challenge = create_code_challenge(code_verify)
    state = generate_state_name()
    authorization_list[state] = code_verify

    params={
        "response_type": "code",
        "client_id": config.client_id,
        "scope": "openid",
        "redirect_uri": config.redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    params = list(f"{k}={v}" for k,v in params.items())
    params = "&".join(params)
    get_url = f"{config.auth_uri}?{params}"
    logging.debug(f"redirect uri: {get_url}")
    return get_url


config = config_load()
serverHost = "127.0.0.1"
serverPort = 8000

class LocalServer(BaseHTTPRequestHandler):
    def _get_params(self, path:str):
        params = {}
        get_query = path.split("?")
        if not len(get_query) == 2:
            return params
        get_params = get_query[1].split("&")
        for get_param in get_params:
            get_vars = get_param.split("=")
            if len(get_vars) == 1:
                params.update({get_vars[0]: None})
            elif len(get_vars) == 2:
                params.update({get_vars[0]: get_vars[1]})
            else:
                logging.warning(f"unable to get data from {get_params}")
        return params

    def _json_response(self, code, message: dict = None):
        data = {"message": "nothing here, move away"}
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if not message:
            message = data
        self.wfile.write(bytes(json.dumps(message), "utf-8"))

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        global GLOBALQ
        path = self.path
        logging.debug(f"path: {path}")
        if path == "/close":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(index_html, "utf-8"))
        elif path == "/":
            self._json_response(200, )
        elif path == "/login":
            GLOBALQ.put(["SSO_LOGIN", 1])
            verify_code = generate_pkce_code()
            logging.debug(f"pkce verify code: {verify_code}")
            url = redirect_to_okta_login(config, verify_code)
            self.send_response(302)
            self.send_header("Location", f"{url}")
            logging.debug(f"redirect url: {url}")
            self.end_headers()
        elif path.startswith("/callback"):
            GLOBALQ.put(["SSO_CALLBACK", 1])
            params = self._get_params(path)
            logging.debug(params)
            code = params.get("code")
            state = params.get("state")
            if not all([code, state]):
                response = {"error": "missing state or code in request"}
                self._json_response(401, response)
            if state not in authorization_list.keys():
                response = {"error": "unknown state or verification code"}
                self._json_response(401, response)
            data = get_access_token(code, state)
            access_token = data.get("access_token")
            if not access_token:
                response = {"error": "unable to get access token"}
                self._json_response(401, response)
            token = decode_token(access_token)
            logging.debug(f"TOKEN: {token}")
            USERMAIL = token.get('sub')
            logging.info(f"user: {USERMAIL}")
            GLOBALQ.put(["SSO_DONE", USERMAIL])
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:8000/close")
            self.end_headers()
        else:
            self.send_response(404)
        self.flush_headers()


def simple_server_run():
    server = ThreadingHTTPServer((serverHost, serverPort), LocalServer)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


class HTTPLocalServer:
    def __init__(self) -> None:
        self.usermail = None
        self.queue = GLOBALQ
        pass

    def start_server(self, q: Queue = None):
        proc = Process(
            target=simple_server_run,
            daemon=True)
        proc.start()
        self.queue.put(["SSO", "Global queue connected"])
        return proc
