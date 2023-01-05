import os
import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        app="fastserver:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
    print("Uvicorn has started")
