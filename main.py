import os
import time
from multiprocessing import Process, Queue
# from fastserver import FastApp, GLOBALQ
from httplocalserver import GLOBALQ, HTTPLocalServer
import webbrowser
import logging


# logging helpers
STANDARD_FORMAT = "%(asctime)s %(name)s %(levelname)s: %(message)s"
DEBUG_FORMAT = "%(asctime)s %(name)s %(levelname)s: %(message)s [%(module)s:%(funcName)s:%(lineno)s]"
if os.path.exists("/etc/sso_debug"):
    print("debug logging enabled")
    logging.basicConfig(level=logging.DEBUG, format=DEBUG_FORMAT)
else:
    logging.basicConfig(level=logging.INFO, format=STANDARD_FORMAT)

SERVERPROC = None
SSO_USERMAIL = None


def start_sso_login():
    
    # some vars
    tries = 0
    browser = True
    max_tries = 5
    max_timeout = 600
    wait_timeout = 1
    timeout = 0
    print_timeout = 5
    
    # start server
    app = HTTPLocalServer()
    SERVERPROC = app.start_server()
    
    
    while SERVERPROC.is_alive():
        
        # start browser just once (or maybe more time)
        if browser:
            logging.info("open default web browser")
            webbrowser.open("http://127.0.0.1:8000/login")
            browser = False
            tries = 0

        # check if we have something in message queue
        try:
            message = GLOBALQ.get(timeout=1)
            logging.debug(f"Q: {message}")
            if message[0] == "SSO_DONE":
                logging.info("we have response from /login")
                SSO_USERMAIL = message[1]
                # wait a while before we close the server
                time.sleep(5)
                SERVERPROC.terminate()
            elif message[0] == "SSO_LOGIN":
                logging.info(f"login number: {tries}")
                tries += 1
        except:
            if (timeout%print_timeout) == 0:
                logging.info(f"local web server is running (up for {timeout} seconds)")

        # too much tries?
        if tries > max_tries:
            logging.warning("maximum number of tries reached, bailing out...")
            SERVERPROC.terminate()
        if timeout > max_timeout:
            logging.critical("timeout")
            SERVERPROC.terminate()

        time.sleep(wait_timeout)
        timeout += wait_timeout
        
    log.info(f"we have usermail: {SSO_USERMAIL}")
    return SSO_USERMAIL

if __name__ == "__main__":
    start_sso_login()
