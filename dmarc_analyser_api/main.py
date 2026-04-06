from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()


@app.get("/ping")
def ping():
    return {"message": "Pong!"}


handler = Mangum(app)
