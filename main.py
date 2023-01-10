import os
import time
from multiprocessing import Process, Queue
# from fastserver import FastApp, GLOBALQ
from httplocalserver import GLOBALQ, HTTPLocalServer
import webbrowser

SERVERPROC = None
SSO_USERMAIL = None


def start_sso_login():
    tries = 0
    max_tries = 5
    max_timeout = 600
    wait_timeout = 1
    timeout = 0
    print_timeout = 5
    app = HTTPLocalServer()
    # queue = Queue()
    SERVERPROC = app.start_server()
    webbrowser.open("http://127.0.0.1:8000/login")
    while SERVERPROC.is_alive():
        try:
            message = GLOBALQ.get(timeout=1)
            print(message)
            if message[0] == "SSO_DONE":
                SSO_USERMAIL = message[1]
                SERVERPROC.terminate()
            elif message[0] == "SSO_LOGIN":
                tries += 1
        except:
            if (timeout%print_timeout) == 0:
                print(f"local web server is running (up for {timeout} seconds)")

        if tries > max_tries:
            print("maximum number of tries reached, bailing out...")
            SERVERPROC.terminate()

        time.sleep(wait_timeout)
        timeout += wait_timeout
        
    print(f"we have usermail: {SSO_USERMAIL}")
    return SSO_USERMAIL

if __name__ == "__main__":
    start_sso_login()
