import os
from typing import Any, Dict, Optional, Union
from urllib.parse import quote
from pydantic import field_validator, PostgresDsn
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
    encoded_password = quote(POSTGRES_PASSWORD, safe='') # safe='' ensures all special characters are encoded

    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "postgres")
    SQLALCHEMY_DATABASE_URI: Union[Optional[PostgresDsn], Optional[str]] = PostgresDsn.build(
        scheme="postgresql",
        username=os.getenv("POSTGRES_USER", "postgres"),
        password=encoded_password,
        host=os.getenv("POSTGRES_HOST", "127.0.0.1:5432"),
        path=f"{os.getenv('POSTGRES_DB', 'postgres')}",
    )


@field_validator("SQLALCHEMY_DATABASE_URI", mode="before")
@classmethod
def assemble_db_connection(v: Optional[str], values: Dict[str, Any]) -> Any:
    if isinstance(v, str):
        return v
    return PostgresDsn.build(
        scheme="postgresql",
        username=values.get("POSTGRES_USER"),
        password=values.get("POSTGRES_PASSWORD"),
        host=values.get("POSTGRES_SERVER"),
        path=f"{values.get('POSTGRES_DB') or ''}",
    )


Configuration = Settings()
