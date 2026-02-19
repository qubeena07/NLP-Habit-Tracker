from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

#sqlite database URL
DATABASE_URL = "sqlite:///./habits.db"

engine = create_engine(DATABASE_URL, 
                       connect_args={"check_same_thread": False})

#session local - for creating independent Db sessions
SessionLocal = sessionmaker(autocommit=False, 
                            autoflush=False,
                              bind=engine)

#Base class for our models
Base = declarative_base()