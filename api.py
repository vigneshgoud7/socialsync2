from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

app = FastAPI(title="SocialSync API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

MONGO_URI = "mongodb+srv://vignesh:Vignesh%4006@social-sync-db.qew1uju.mongodb.net/?appName=social-sync-db"
client = AsyncIOMotorClient(MONGO_URI)
db = client["social_sync"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SignupRequest(BaseModel):
    fullname: str
    username: str
    email: EmailStr
    phone: str
    password: str
    profile_photo: Optional[str] = None

class LoginRequest(BaseModel):
    identifier: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def hash_password(p): return pwd_context.hash(p)
def verify_password(p,h): return pwd_context.verify(p,h)

def create_access_token(data):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, ALGORITHM)

@app.post("/signup", status_code=201)
async def signup(payload: SignupRequest):
    print("DEBUG password:", payload.password)
    print("DEBUG byte length:", len(payload.password.encode("utf-8")))

    if await db.users.find_one({"email":payload.email}):
        raise HTTPException(400,"Email already exists")
    if await db.users.find_one({"username":payload.username}):
        raise HTTPException(400,"Username already exists")
    if await db.users.find_one({"phone":payload.phone}):
        raise HTTPException(400,"Phone already exists")

    await db.users.insert_one({
        "fullname": payload.fullname,
        "username": payload.username,
        "email": payload.email,
        "phone": payload.phone,
        "password": hash_password(payload.password),
        "profile_photo": payload.profile_photo,
        "created_at": datetime.utcnow()
    })
    return {"message":"User created"}

@app.post("/login", response_model=Token)
async def login(payload: LoginRequest):
    user = await db.users.find_one({
        "$or":[
            {"email":payload.identifier},
            {"username":payload.identifier},
            {"phone":payload.identifier}
        ]
    })
    if not user: raise HTTPException(400,"Incorrect credentials")
    if not verify_password(payload.password, user["password"]):
        raise HTTPException(400,"Incorrect credentials")

    token = create_access_token({
        "sub": user.get("email"),
        "username": user.get("username")
    })
    return {"access_token":token,"token_type":"bearer"}

@app.get("/")
def home():
    return {"message":"API running"}
