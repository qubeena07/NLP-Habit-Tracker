from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import auth
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm
from typing import List
import models
import schemas



#create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Habit Tracker API")

#create user
@app.post("/signup",response_model=schemas.UserOut)
def creat_user(user:schemas.UserCreate, db: Session = Depends(auth.get_db)):
    #check if user already exists
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    #create new user
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

#login user
@app.post("/login",response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(auth.get_db)):
    #authenticate user
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    #create access token
    access_token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

#create habits
@app.post("/habits/",response_model=schemas.HabitOut)
def create_habit(habit: schemas.HabitCreate, db: Session = Depends(auth.get_db), current_user: models.User = Depends(auth.get_current_user)):
    db_habit = models.HabitRecord(**habit.model_dump(),user_id=current_user.id)
    db.add(db_habit)
    db.commit()
    db.refresh(db_habit)
    return db_habit


#read habits
@app.get("/habits/",response_model=List[schemas.HabitOut])
def read_habits(skip: int = 0, limit: int = 100, 
                db: Session = Depends(auth.get_db),
                current_user: models.User = Depends(auth.get_current_user)):
    habits = db.query(models.HabitRecord).filter(models.HabitRecord.user_id==current_user.id).offset(skip).limit(limit).all()
    return habits

#read habits by ID
@app.get("/habits/{habit_id}",response_model=schemas.HabitOut)
def read_habits_id(habit_id: int, db: Session = Depends(auth.get_db)):
    db_habit = db.query(models.HabitRecord).filter(models.HabitRecord.id == habit_id).first()
    if db_habit is None:
        raise HTTPException(status_code=404, detail="Habit not found")
    return db_habit

#update habits
@app.put("/habits/{habit_id}",response_model=schemas.HabitOut)
def update_habit(habit_id: int, habit: schemas.HabitCreate, db: Session = Depends(auth.get_db)):
    db_habit = db.query(models.HabitRecord).filter(models.HabitRecord.id == habit_id).first()
    if db_habit is None:
        raise HTTPException(status_code=404, detail="Habit not found")
    for key, value in habit.model_dump().items():
        setattr(db_habit, key, value)
    db.commit()
    db.refresh(db_habit)
    return db_habit

#delete habits
@app.delete("/habits/{habit_id}")
def delete_habit(habit_id: int, db: Session = Depends(auth.get_db)):
    db_habit = db.query(models.HabitRecord).filter(models.HabitRecord.id == habit_id).first()
    if db_habit is None:
        raise HTTPException(status_code=404, detail="Habit not found")
    db.delete(db_habit)
    db.commit()
    return {"detail": "Habit deleted"}