"""Calendar provider adapters behind one interface.

* ``GoogleCalendarProvider`` — Google Calendar API v3 (OAuth2 refresh-token credentials).
* ``Microsoft365CalendarProvider`` — Microsoft Graph (client-credentials, application access
  restricted to the booking mailbox via an Exchange application access policy).
* ``LocalCalendarProvider`` — database-only calendar for development and tenants without a
  connected calendar.

Credentials are read from the secret manager at call time and never leave this service.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import quote

import httpx

from platform_core.errors import UpstreamUnavailable

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_API = "https://www.googleapis.com/calendar/v3"
GRAPH_API = "https://graph.microsoft.com/v1.0"


@dataclass(frozen=True)
class EventSpec:
    event_key: str  # deterministic id derived from the appointment id (idempotency)
    summary: str
    description: str
    starts_at: datetime
    ends_at: datetime
    timezone: str
    attendee_email: str | None = None


class CalendarProvider(Protocol):
    name: str

    async def busy(self, calendar_id: str, start: datetime, end: datetime
                   ) -> list[tuple[datetime, datetime]]: ...

    async def create_event(self, calendar_id: str, spec: EventSpec) -> str: ...

    async def move_event(self, calendar_id: str, external_id: str, spec: EventSpec) -> None: ...

    async def cancel_event(self, calendar_id: str, external_id: str) -> None: ...


def _parse(dt: str) -> datetime:
    parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class LocalCalendarProvider:
    name = "local"

    async def busy(self, calendar_id: str, start: datetime, end: datetime
                   ) -> list[tuple[datetime, datetime]]:
        return []  # bookings in the database are always merged in by the service

    async def create_event(self, calendar_id: str, spec: EventSpec) -> str:
        return f"local-{spec.event_key}"

    async def move_event(self, calendar_id: str, external_id: str, spec: EventSpec) -> None:
        return None

    async def cancel_event(self, calendar_id: str, external_id: str) -> None:
        return None


class _TokenCache:
    def __init__(self) -> None:
        self.token: str | None = None
        self.expires = 0.0

    def valid(self) -> bool:
        return self.token is not None and time.monotonic() < self.expires - 60


class GoogleCalendarProvider:
    name = "google"

    def __init__(self, credentials_json: str, client: httpx.AsyncClient | None = None) -> None:
        creds = json.loads(credentials_json)
        self._client_id = creds["client_id"]
        self._client_secret = creds["client_secret"]
        self._refresh_token = creds["refresh_token"]
        self._http = client or httpx.AsyncClient(timeout=15)
        self._token = _TokenCache()

    async def _auth(self) -> dict[str, str]:
        if not self._token.valid():
            resp = await self._http.post(GOOGLE_TOKEN_URL, data={
                "grant_type": "refresh_token", "client_id": self._client_id,
                "client_secret": self._client_secret, "refresh_token": self._refresh_token})
            if resp.status_code != 200:
                raise UpstreamUnavailable("google auth failed")
            body = resp.json()
            self._token.token = body["access_token"]
            self._token.expires = time.monotonic() + int(body.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self._token.token}"}

    async def busy(self, calendar_id: str, start: datetime, end: datetime
                   ) -> list[tuple[datetime, datetime]]:
        resp = await self._http.post(f"{GOOGLE_API}/freeBusy", headers=await self._auth(), json={
            "timeMin": start.isoformat(), "timeMax": end.isoformat(),
            "items": [{"id": calendar_id}]})
        if resp.status_code != 200:
            raise UpstreamUnavailable("google freeBusy failed")
        cal = resp.json()["calendars"].get(calendar_id, {})
        if cal.get("errors"):
            raise UpstreamUnavailable("google calendar not accessible")
        return [(_parse(b["start"]), _parse(b["end"])) for b in cal.get("busy", [])]

    def _event_body(self, spec: EventSpec) -> dict:
        body: dict = {
            "summary": spec.summary, "description": spec.description,
            "start": {"dateTime": spec.starts_at.isoformat(), "timeZone": spec.timezone},
            "end": {"dateTime": spec.ends_at.isoformat(), "timeZone": spec.timezone},
        }
        if spec.attendee_email:
            body["attendees"] = [{"email": spec.attendee_email}]
        return body

    async def create_event(self, calendar_id: str, spec: EventSpec) -> str:
        # Google accepts client-supplied ids (base32hex); a retry with the same id → 409.
        event_id = spec.event_key.replace("-", "").lower()
        resp = await self._http.post(
            f"{GOOGLE_API}/calendars/{quote(calendar_id, safe="")}/events",
            params={"sendUpdates": "all" if spec.attendee_email else "none"},
            headers=await self._auth(), json={"id": event_id, **self._event_body(spec)})
        if resp.status_code in (200, 201, 409):
            return event_id
        raise UpstreamUnavailable("google event creation failed")

    async def move_event(self, calendar_id: str, external_id: str, spec: EventSpec) -> None:
        resp = await self._http.patch(
            f"{GOOGLE_API}/calendars/{quote(calendar_id, safe="")}/events/{external_id}",
            headers=await self._auth(), json=self._event_body(spec))
        if resp.status_code != 200:
            raise UpstreamUnavailable("google event update failed")

    async def cancel_event(self, calendar_id: str, external_id: str) -> None:
        resp = await self._http.delete(
            f"{GOOGLE_API}/calendars/{quote(calendar_id, safe="")}/events/{external_id}",
            headers=await self._auth())
        if resp.status_code not in (200, 204, 404, 410):
            raise UpstreamUnavailable("google event cancellation failed")


class Microsoft365CalendarProvider:
    name = "microsoft365"

    def __init__(self, credentials_json: str, client: httpx.AsyncClient | None = None) -> None:
        creds = json.loads(credentials_json)
        self._tenant = creds["tenant_id"]
        self._client_id = creds["client_id"]
        self._client_secret = creds["client_secret"]
        self._http = client or httpx.AsyncClient(timeout=15)
        self._token = _TokenCache()

    async def _auth(self) -> dict[str, str]:
        if not self._token.valid():
            resp = await self._http.post(
                f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": self._client_id,
                      "client_secret": self._client_secret,
                      "scope": "https://graph.microsoft.com/.default"})
            if resp.status_code != 200:
                raise UpstreamUnavailable("microsoft auth failed")
            body = resp.json()
            self._token.token = body["access_token"]
            self._token.expires = time.monotonic() + int(body.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self._token.token}"}

    async def busy(self, calendar_id: str, start: datetime, end: datetime
                   ) -> list[tuple[datetime, datetime]]:
        resp = await self._http.post(
            f"{GRAPH_API}/users/{calendar_id}/calendar/getSchedule", headers=await self._auth(),
            json={"schedules": [calendar_id],
                  "startTime": {"dateTime": start.astimezone(UTC).replace(tzinfo=None).isoformat(),
                                "timeZone": "UTC"},
                  "endTime": {"dateTime": end.astimezone(UTC).replace(tzinfo=None).isoformat(),
                              "timeZone": "UTC"},
                  "availabilityViewInterval": 15})
        if resp.status_code != 200:
            raise UpstreamUnavailable("graph getSchedule failed")
        items = resp.json()["value"][0].get("scheduleItems", [])
        return [(_parse(i["start"]["dateTime"]).replace(tzinfo=UTC),
                 _parse(i["end"]["dateTime"]).replace(tzinfo=UTC))
                for i in items if i.get("status") != "free"]

    def _event_body(self, spec: EventSpec) -> dict:
        body: dict = {
            "subject": spec.summary,
            "body": {"contentType": "text", "content": spec.description},
            "start": {"dateTime": spec.starts_at.astimezone(UTC).replace(tzinfo=None).isoformat(),
                      "timeZone": "UTC"},
            "end": {"dateTime": spec.ends_at.astimezone(UTC).replace(tzinfo=None).isoformat(),
                    "timeZone": "UTC"},
        }
        if spec.attendee_email:
            body["attendees"] = [{"emailAddress": {"address": spec.attendee_email},
                                  "type": "required"}]
        return body

    async def create_event(self, calendar_id: str, spec: EventSpec) -> str:
        # transactionId makes Graph event creation idempotent across retries.
        resp = await self._http.post(f"{GRAPH_API}/users/{calendar_id}/calendar/events",
                                     headers=await self._auth(),
                                     json={**self._event_body(spec), "transactionId": spec.event_key})
        if resp.status_code not in (200, 201):
            raise UpstreamUnavailable("graph event creation failed")
        return resp.json()["id"]

    async def move_event(self, calendar_id: str, external_id: str, spec: EventSpec) -> None:
        resp = await self._http.patch(f"{GRAPH_API}/users/{calendar_id}/events/{external_id}",
                                      headers=await self._auth(), json=self._event_body(spec))
        if resp.status_code != 200:
            raise UpstreamUnavailable("graph event update failed")

    async def cancel_event(self, calendar_id: str, external_id: str) -> None:
        resp = await self._http.post(f"{GRAPH_API}/users/{calendar_id}/events/{external_id}/cancel",
                                     headers=await self._auth(), json={"comment": "Cancelled"})
        if resp.status_code not in (202, 204, 404):
            raise UpstreamUnavailable("graph event cancellation failed")
