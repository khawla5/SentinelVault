"""Pydantic request/response models for the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# --- Auth ---
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    master_password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    username: str
    master_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


# --- Vault ---
class VaultEntryCreate(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    username: str = ""
    url: str = ""
    password: str = Field(min_length=1)


class VaultEntryOut(BaseModel):
    id: int
    label: str
    username: str
    url: str
    created_at: datetime
    updated_at: datetime


class VaultEntryReveal(VaultEntryOut):
    password: str  # decrypted on demand; caller should minimise its lifetime


# --- Tools ---
class GenerateRequest(BaseModel):
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True


class GenerateResponse(BaseModel):
    password: str


class StrengthRequest(BaseModel):
    password: str


class StrengthResponse(BaseModel):
    rating: str
    entropy_bits: float
    pool_size: int
    suggestions: list[str]


class LeakResponse(BaseModel):
    breached: bool
    count: int


class LogOut(BaseModel):
    id: int
    event: str
    detail: str
    ip_address: str
    machine_name: str
    timestamp: datetime
