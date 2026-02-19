from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import SessionLocal
import jwt, models
import os
import hashlib
from dotenv import load_dotenv

#security configurations
SECRET_KEY = os.getenv("SECRET_KEY")
# SECRET_KEY = "ab75b656570053475546974f61e1275a444eb5411d55f80e98dacc1f0cfb4e72"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#tells fastapi where login endpoint is
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password:str):
    prepared_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return pwd_context.hash(prepared_password)

def verify_password(plain_password, hashed_password):
    prepared_password = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(prepared_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user