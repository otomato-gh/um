from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import datetime

import database
import schemas
import security

app = FastAPI()


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="login")),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(
            token, security.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Could not validate credentials"
            )
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db.query(database.User).filter(database.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.post("/register", response_model=schemas.UserResponse)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if username or email already exists
    existing_user = (
        db.query(database.User)
        .filter(
            (database.User.username == user.username)
            | (database.User.email == user.email)
        )
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    # Create new user
    hashed_password = security.get_password_hash(user.password)
    db_user = database.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/login")
def login_user(user_login: schemas.UserLogin, db: Session = Depends(get_db)):
    # Find user by username
    user = (
        db.query(database.User)
        .filter(database.User.username == user_login.username)
        .first()
    )

    if not user or not security.verify_password(
        user_login.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Update last login time
    user.last_login = datetime.utcnow()
    db.commit()

    # Generate access token
    access_token = security.create_access_token(data={"sub": user.username})

    return {"access_token": access_token, "token_type": "bearer"}


@app.put("/update", response_model=schemas.UserResponse)
def update_user(
    user_update: schemas.UserUpdate,
    current_user: database.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Update user details
    if user_update.full_name is not None:
        current_user.full_name = user_update.full_name

    if user_update.email is not None:
        # Check if new email is already in use
        existing_email = (
            db.query(database.User)
            .filter(
                (database.User.email == user_update.email)
                & (database.User.id != current_user.id)
            )
            .first()
        )

        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use"
            )

        current_user.email = user_update.email

    db.commit()
    db.refresh(current_user)

    return current_user
