import os
import uvicorn
import time
from multiprocessing import Process, Queue
from fastserver import FastApp, GLOBALQ
import webbrowser

SERVERPROC = None
SSO_USERMAIL = None

if __name__ == "__main__":
    app = FastApp()
    # queue = Queue()
    SERVERPROC = app.start_server()
    webbrowser.open("http://127.0.0.1:8000/login")
    while SERVERPROC.is_alive():
        time.sleep(2)
        try:
            message = GLOBALQ.get(timeout=1)
            print(message)
            if message[0] == "SSO_DONE":
                SSO_USERMAIL = message[1]
                SERVERPROC.terminate()
        except:
            print("uvicorn is running")
        
    print(f"we have usermail: {SSO_USERMAIL}")

