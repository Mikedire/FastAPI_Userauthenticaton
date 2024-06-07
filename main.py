from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# Generate a secure key using Python (uncomment to generate a new key)
# import os
# SECRET_KEY = os.urandom(32).hex()

# Secret key for encoding JWT
SECRET_KEY = "8c42b8a80a129960619790113b210c4b0d65359fd35710e786729079cf85ec2c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Fake database for demonstration purposes
db = {
    "tim": {
        "username": "tim",
        "full_name": "Mik Ruscica",
        "email": "mik@gmail.com",
        "hashed_password": "$2b$12$KIX6/DPdFZ7r/U3.RJsNT.eHL9E.MWVb2HrAfmCR6Wg9ni6APDQNe",  # bcrypt hashed "password"
        "disabled": False
    }
}

# Pydantic models for data validation
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None  # Corrected type hinting

class User(BaseModel):
    username: str
    email: str | None = None  # Corrected type hinting
    full_name: str | None = None  # Corrected type hinting
    disabled: bool | None = None  # Corrected type hinting

class UserInDB(User):
    hashed_password: str

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # Fixed typo from 'depreacted' to 'deprecated'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# Utility functions for password handling and user authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Function to create JWT access tokens
def create_access_token(data: dict, expires_delta: timedelta | None = None):  # Corrected type hinting
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get the current user from the token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)  # Changed 'db' to 'fake_db' for consistency
    if user is None:
        raise credentials_exception
    return user

# Dependency to get the current active user
async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Route to obtain a JWT token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)  # Changed 'User' to 'user'
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Route to get the current user's information
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Route to get the current user's items
@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": 1, "owner": current_user}]

# Generate a hashed password (for demonstration)
pwd = get_password_hash("mickie1234")
print(pwd)
