from sqlmodel import select
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from models.user import User  
from db.init_db import SessionDep, get_session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from typing import Annotated 
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt
import os

app = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90

oauth_scheme = OAuth2PasswordBearer(tokenUrl="/token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None  


class UserInDB(User):
    hashed_password: str

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return password_context.hash(password)


def get_user(db: Session, name: str):
    statement = select(User).where(User.name == name)
    user = db.exec(statement).first()
    if user:
        return UserInDB(**user.model_dump())
    return None


def authenticate_user(db: Session, name: str, password: str):
    user = get_user(db, name)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(SessionDep)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        name = payload.get("sub")
        if name is None:
            raise credentials_exception
        token_data = TokenData(username=name) 
    except JWTError:
        raise credentials_exception
    user = get_user(db, name=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if getattr(current_user, "disabled", False):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/register/")
def create_user(user: User, session: Session = Depends(SessionDep)):
    hashed_password = get_password_hash(user.hashed_password)
    user.hashed_password = hashed_password
    if hasattr(user, "hasged_password"):
     delattr(user, "hashed_password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.get("/home/me")
async def user_me(
    current_user: Annotated[User, Depends(get_current_active_user)],):
    return current_user
    

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(SessionDep)],
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.name}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer") 
if status.HTTP_200_OK:
    redirect=status.HTTP_200_OK,
detail="User created successfully",
headers={"Location": "/home/me"}
