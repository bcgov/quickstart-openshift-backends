# Shared properties

from pydantic import ConfigDict, BaseModel, EmailStr


class UserBase(BaseModel):
    name: str
    email: EmailStr


# Properties to receive via API on update
class User(UserBase):
    user_id: int


class UserInDBBase(UserBase):
    id: int
    model_config = ConfigDict(from_attributes=True)
