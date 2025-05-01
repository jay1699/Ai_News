from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import json
import os
import openai
from dotenv import load_dotenv

# ========== Configuration ==========

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load variables from .env
USERS_DB_FILE = "users_db.json"
SECRET_KEY = os.getenv("SECRET_KEY")  # Get from .env file
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# ========== Data Models ==========

class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    credits: int = 5

class UserCreate(BaseModel):
    username: str
    full_name: Optional[str] = None
    password: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ========== Utils ==========

def load_users_db():
    if not os.path.exists(USERS_DB_FILE):
        with open(USERS_DB_FILE, "w") as f:
            json.dump({}, f)
    with open(USERS_DB_FILE, "r") as f:
        return json.load(f)

def save_users_db(users_db):
    with open(USERS_DB_FILE, "w") as f:
        json.dump(users_db, f)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        return UserInDB(**db[username])
    return None

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        users_db = load_users_db()
        user = get_user(users_db, username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid credentials")

# ========== Routes ==========

@app.post("/auth/signup")
def signup(user: UserCreate):
    users_db = load_users_db()
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    user_in_db = UserInDB(
        username=user.username,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        credits=5
    )
    users_db[user.username] = user_in_db.dict()
    save_users_db(users_db)
    return {"message": "User created successfully"}

@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users_db = load_users_db()
    user = authenticate_user(users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/credits")
def get_credits(current_user: User = Depends(get_current_user)):
    users_db = load_users_db()
    return {"credits": users_db[current_user.username]["credits"]}

@app.get("/ai-news")
def generate_ai_news(current_user: User = Depends(get_current_user)):
    users_db = load_users_db()
    user_data = users_db.get(current_user.username)

    if user_data["credits"] <= 0:
        raise HTTPException(status_code=403, detail="Not enough credits")

    try:
        openai.api_key = os.getenv("OPENAI_API_KEY")  # Use the OpenAI API key from .env
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Generate the latest AI news headlines"}],
            max_tokens=100
        )
        ai_news = response.choices[0].message.content.strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Deduct 1 credit and save
    user_data["credits"] -= 1
    save_users_db(users_db)

    return {"ai_news": ai_news}
