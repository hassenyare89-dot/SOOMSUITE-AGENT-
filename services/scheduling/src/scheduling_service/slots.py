"""Pure, timezone-aware slot computation (unit-tested without I/O)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from platform_core.errors import ValidationFailed

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DEFAULT_HOURS = {d: [["09:00", "17:00"]] for d in WEEKDAYS[:5]}


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationFailed("unknown timezone") from exc


@dataclass(frozen=True)
class BookingRules:
    business_timezone: str = "UTC"
    working_hours: dict[str, list[list[str]]] = field(default_factory=lambda: DEFAULT_HOURS)
    min_notice_minutes: int = 120
    max_days_ahead: int = 30
    slot_step_minutes: int = 30
    holidays: tuple[str, ...] = ()

    @classmethod
    def from_dicts(cls, *layers: dict) -> BookingRules:
        merged: dict = {}
        for layer in layers:
            merged.update({k: v for k, v in (layer or {}).items() if v is not None})
        return cls(
            business_timezone=merged.get("business_timezone", "UTC"),
            working_hours=merged.get("working_hours", DEFAULT_HOURS),
            min_notice_minutes=int(merged.get("min_notice_minutes", 120)),
            max_days_ahead=int(merged.get("max_days_ahead", 30)),
            slot_step_minutes=int(merged.get("slot_step_minutes", 30)),
            holidays=tuple(merged.get("holidays", ())),
        )


def _overlaps(a0: datetime, a1: datetime, b0: datetime, b1: datetime) -> bool:
    return a0 < b1 and b0 < a1


def candidate_slots(
    rules: BookingRules,
    *,
    duration: timedelta,
    buffer: timedelta,
    now: datetime,
    earliest: datetime | None,
    days: int,
    busy: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """All free slots inside working hours (business TZ), respecting notice, horizon, buffers."""
    tz = zone(rules.business_timezone)
    start_bound = max(now + timedelta(minutes=rules.min_notice_minutes), earliest or now)
    horizon = now + timedelta(days=min(days, rules.max_days_ahead))
    step = timedelta(minutes=rules.slot_step_minutes)
    out: list[tuple[datetime, datetime]] = []
    day: date = start_bound.astimezone(tz).date()
    while datetime.combine(day, time.min, tz) < horizon:
        if day.isoformat() not in rules.holidays:
            for window in rules.working_hours.get(WEEKDAYS[day.weekday()], []):
                w0 = datetime.combine(day, time.fromisoformat(window[0]), tz)
                w1 = datetime.combine(day, time.fromisoformat(window[1]), tz)
                cursor = w0
                while cursor + duration <= w1:
                    s0, s1 = cursor.astimezone(UTC), (cursor + duration).astimezone(UTC)
                    if s0 >= start_bound and s1 <= horizon and not any(
                        _overlaps(s0 - buffer, s1 + buffer, b0, b1) for b0, b1 in busy
                    ):
                        out.append((s0, s1))
                    cursor += step
        day += timedelta(days=1)
    return out


def spread(slots: list[tuple[datetime, datetime]], n: int) -> list[tuple[datetime, datetime]]:
    """Choose up to n slots spread across the available range (not n adjacent ones)."""
    if len(slots) <= n:
        return slots
    chosen: list[tuple[datetime, datetime]] = []
    used_days: set = set()
    for s in slots:  # first pass: at most one per day
        if s[0].date() not in used_days:
            chosen.append(s)
            used_days.add(s[0].date())
        if len(chosen) == n:
            return chosen
    for s in slots:
        if s not in chosen:
            chosen.append(s)
        if len(chosen) == n:
            break
    return sorted(chosen)


def display(dt: datetime, tz_name: str) -> str:
    local = dt.astimezone(zone(tz_name))
    return f"{local:%a %d %b, %H:%M} ({tz_name})"
