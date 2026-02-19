from datetime import datetime, timezone
from database import Base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    #relationship to habits
    habits = relationship("HabitRecord", back_populates="owner")

class HabitRecord(Base):
    __tablename__ = "habit_records"

    id = Column(Integer, primary_key=True, index=True)
    user_input = Column(String, index=True)
    parsed_category = Column(String, index=True,nullable=True)
    quantity = Column(Integer, default=1)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    #foreign key to user
    user_id = Column(Integer, ForeignKey("users.id"))
    #relationship to user
    owner = relationship("User", back_populates="habits")