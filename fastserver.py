import httpx
import json
import logging
import base64
import random
import string
import hashlib
import os
import uvicorn


from fastapi import Depends, FastAPI, HTTPException, Request, Response, Cookie
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from starlette.config import Config
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
  <p>Thanks USER_EMAIL</p>
  <h1>You can close this window now</h1>
  <!-- <button onclick="window.close()">Close Window</button> -->
</body>
</html>
"""


USERMAIL = None


class ssoConfig(BaseModel):
    auth_uri: str
    client_id: str
    redirect_uri: str
    issuer: str
    token_uri: str
    userinfo_uri: str

class SSOException(Exception):
    def __init__(self, status: int = 400, message: str = "No details") -> None:
        log.warning(f"SOO exception: {message} [{status}]")
        self.message = message
        self.status = status
        pass


# logging helpers
if os.path.exists("/etc/sso_debug"):
    logging.basicConfig(level=logging.DEBUG)

log = logging

def config_load(filename: str = "secret.json") -> ssoConfig:
    config = None
    with open(filename) as f:
        config = json.load(f)
    config = ssoConfig(**config)
    return config

async def generate_pkce_code(size: int = 48):
    characters = string.ascii_letters + string.digits
    rand_string = "".join(
        list(random.choice(characters) for x in range(0,size))
    )
    return rand_string

async def create_code_challenge(code: str):
    challenge = hashlib.sha256(code.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(challenge).decode()
    challenge = challenge.replace("=", "")
    return challenge

async def generate_state_name():
    return await generate_pkce_code(16)


async def get_access_token(
        code: str, state: str
    ):

    verify_code = authorization_list.get(state)
    log.debug(f"verify code: {verify_code}")
    
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

    log.debug(f"request data: {data}")

    request = httpx.post(
        url=config.token_uri,
        data=data,
        follow_redirects=False
    )

    log.debug(request)
    log.info(f"request status: {request.status_code}")
    log.debug(f"token: {request.text}")

    if (not request.status_code == 200 or not request.json()):
        raise SSOException(message="unable to request token from Okta")

    return request.json()


async def decode_token(data: str):
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


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
config = config_load()

async def redirect_to_okta_login(
    request: Request,
    config: ssoConfig,
    code_verify: str
    ):

    challenge = await create_code_challenge(code_verify)
    state = await generate_state_name()
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
    log.debug(f"redirect uri: {get_url}")
    return RedirectResponse(get_url)


@app.exception_handler(SSOException)
async def hubgrade_exception_handler(request: Request, exc: SSOException) -> Response:
    return JSONResponse(
        status_code= exc.status,
        content={
            "message": exc.message,
        }
    )


@app.get("/login", response_class=RedirectResponse)
async def login(
        request: Request
    ) -> RedirectResponse:
    verify_code = await generate_pkce_code()
    log.debug(f"verify code: {verify_code}")
    return await redirect_to_okta_login(request, config, verify_code)


@app.get("/callback")
async def callback(
        request: Request
    ):

    params = request.query_params
    code = params.get("code")
    state = params.get("state")
    if not all([code, state]):
        raise SSOException(message="code or state not present")

    if state not in authorization_list.keys():
        raise SSOException(message="unknown state code, please login again")

    data = await get_access_token(code, state)
    access_token = data.get("access_token")
    if not access_token:
        raise SSOException(message="unable to get access token")
    token = await decode_token(access_token)
    log.debug(f"TOKEN: {token}")
    log.info(f"user: {token.get('sub')}")

    response = RedirectResponse("/close")
    response.set_cookie(key="usermail", value=token.get("sub"))
    return response


@app.get("/close")
async def close_now(
        request: Request
    ):
    global index_html
    global USERMAIL

    usermail = request.cookies.get("usermail")
    index_html = index_html.replace("USER_EMAIL", usermail)
    USERMAIL = usermail
    GLOBALQ.put(["SSO_DONE", USERMAIL])

    return HTMLResponse(
        content=index_html
    )

@app.get("/authlist")
async def get_authlist():
    return authorization_list


class FastApp:
    def __init__(self) -> None:
        self.usermail = None
        self.queue = GLOBALQ
        pass

    def start_server(self, q: Queue = None):
        proc = Process(
            target=uvicorn.run,
            args=(app,),
            kwargs={
                "host": "127.0.0.1",
                "port": 8000,
                "log_level": "info"
                },
            daemon=True)
        proc.start()
        # self.queue = q
        self.queue.put(["SSO", "Global queue connected"])
        return proc
    