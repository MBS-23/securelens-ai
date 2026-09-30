from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, max_length: int = 100) -> str:
    slug = SLUG_RE.sub("-", value.lower()).strip("-")
    return (slug or "item")[:max_length].strip("-") or "item"


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class PageParams(BaseModel):
    page: int = Field(1, ge=1, le=100000)
    page_size: int = Field(50, ge=1, le=200)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class IdOut(ORMModel):
    id: uuid.UUID


class Message(BaseModel):
    message: str


class TimestampedOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
