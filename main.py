from fastapi import FastAPI, Request, Form, Depends, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient

from pydantic import BaseModel

app       = FastAPI()
templates = Jinja2Templates(directory="templates")

MONGO_URL       = "mongodb://localhost:27017"
client          = AsyncIOMotorClient(MONGO_URL)
db              = client["user_db"]       
user_collection = db["users"]  

class SignupRequest(BaseModel):
    nickname: str
    email   : str
    password: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/signup")
async def signup(
    nickname: str = Form(None),
    email   : str = Form(None),
    password: str = Form(None)
):
    existing_user = await user_collection.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="信箱已經被註冊")

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    new_user = {
        "nickname": nickname,
        "email"   : email,
        "password": hashed_pw.decode("utf-8")
    }
    await user_collection.insert_one(new_user)
    return RedirectResponse(url="/?success=1", status_code=302)


@app.post("/signin")
async def signin(
    email   : str = Form(None),
    password: str = Form(None)
):
    user = await user_collection.find_one({"email": email})
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return RedirectResponse(url="/?error=帳號或密碼錯誤", status_code=302)

    response = RedirectResponse(url="/member", status_code=302)
    response.set_cookie(key="nickname", value=user["nickname"])
    return response


@app.get("/signout")
async def signout():
    response = RedirectResponse(url="/")
    response.delete_cookie("nickname")
    return response


@app.get("/member", response_class=HTMLResponse)
async def member(request: Request, nickname: str = Cookie(default=None)):
    if not nickname:
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse("member.html", {"request": request, "nickname": nickname})
