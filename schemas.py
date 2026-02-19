from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional

#token schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


#user schemas
class UserCreate(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    email: str

    model_config = ConfigDict(from_attributes=True)


#habit schemas
#shared properties
class HabitBase(BaseModel):
    user_input: str
    parsed_category: Optional[str] = None
    quantity: Optional[int] = 1

#creating record - inherits base
class HabitCreate(HabitBase):
    pass

#reading record - adds ID and timestamp
class HabitOut(HabitBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HabitNLPInput(BaseModel):
    raw_txt: str