import os
from urllib.parse import quote
from typing import Optional, Union, Dict, Any
from pydantic import PostgresDsn, field_validator
from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "127.0.0.1")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", "5432")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = quote(os.getenv("POSTGRES_PASSWORD", "postgres"), safe='')
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "postgres")
    SQLALCHEMY_DATABASE_URI: Union[Optional[PostgresDsn], Optional[str]] = None

    @field_validator("SQLALCHEMY_DATABASE_URI", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        print(f"assemble_db_connection called with v: {v}, values: {values}")
        if isinstance(v, str):
            return v
        dsn = PostgresDsn.build(
            scheme="postgresql",
            username=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_HOST"),
            port=int(values.get("POSTGRES_PORT")),
            path=f"{values.get('POSTGRES_DB') or ''}",
        )
        print(f"Constructed SQLALCHEMY_DATABASE_URI: {dsn}")
        return dsn

Configuration = Settings()
print(f"Final SQLALCHEMY_DATABASE_URI: {Configuration.SQLALCHEMY_DATABASE_URI}")