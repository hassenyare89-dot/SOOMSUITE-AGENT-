from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from platform_core.schemas.common import StrictModel
from platform_core.schemas.enums import Channel


class Card(BaseModel):
    """Structured UI element. Rendered by the widget as components, never as HTML."""

    type: Literal["slots", "contact_form", "escalation", "sources", "pricing", "appointment",
                  "quick_replies"]
    data: dict[str, Any]


class InboundMessage(StrictModel):
    channel: Channel
    conversation_ref: str = Field(min_length=8, max_length=128)
    text: str = Field(min_length=1, max_length=4000)
    external_message_id: str | None = Field(default=None, max_length=200)
    selected_slot_token: str | None = Field(default=None, max_length=2000)
    customer_timezone: str | None = Field(default=None, max_length=64)


class ChatReply(BaseModel):
    conversation_id: UUID
    message_id: UUID
    text: str
    cards: list[Card] = []
    escalated: bool = False
    handled_by: Literal["samiir", "human"] = "samiir"
