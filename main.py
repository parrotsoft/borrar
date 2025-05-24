from fastapi import FastAPI, Depends
from pydantic import BaseModel

from fastapi.security import OAuth2PasswordBearer
from fastapi.exceptions import HTTPException

from typing import Annotated

from jose import jwt

app = FastAPI()

users = {
    "miguel": { "username": "miguel", "full_name": "Miguel Grinberg", "email": "miguel@example.com", "password": "password"},
    "maria": { "username": "maria", "full_name": "Maria Ramos", "email": "maria@example.com", "password": "password"}
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserLogin(BaseModel):
    username: str
    password: str

def encode_token(data: dict):
    token = jwt.encode(data, "secret", algorithm="HS256")
    return token
    

def decode_token(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        data = jwt.decode(token, "secret", algorithms="HS256")
        user = users.get(data['username'])

        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        
        return user

    except jwt.JWTError as e:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.get("/")
async def root():
    return {"message": "Hola Miguel"}

@app.post("/login")
def login(user_data: UserLogin):
    user = users.get(user_data.username)

    if not user or user_data.password != user['password']:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    token = encode_token({"username": user_data.username, "full_name": user['full_name']})

    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/list", dependencies=[Depends(decode_token)])
def user_list():
    return users