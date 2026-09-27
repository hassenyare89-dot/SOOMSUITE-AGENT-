from datetime import UTC, datetime, timedelta

import pytest

from platform_core.errors import ValidationFailed
from scheduling_service.slots import BookingRules, candidate_slots, display, spread, zone

MONDAY = datetime(2026, 9, 28, 6, 0, tzinfo=UTC)


def test_slots_respect_business_timezone_and_hours():
    rules = BookingRules(business_timezone="Africa/Nairobi", min_notice_minutes=0,
                         working_hours={"mon": [["09:00", "11:00"]]})
    slots = candidate_slots(rules, duration=timedelta(minutes=30), buffer=timedelta(0),
                            now=MONDAY, earliest=None, days=1, busy=[])
    # 09:00 Nairobi (UTC+3) == 06:00 UTC
    assert slots[0][0] == datetime(2026, 9, 28, 6, 0, tzinfo=UTC)
    assert slots[-1][1] <= datetime(2026, 9, 28, 8, 0, tzinfo=UTC)
    assert len(slots) == 4


def test_busy_times_and_buffers_are_excluded():
    rules = BookingRules(min_notice_minutes=0, working_hours={"mon": [["06:00", "08:00"]]})
    busy = [(datetime(2026, 9, 28, 6, 30, tzinfo=UTC), datetime(2026, 9, 28, 7, 0, tzinfo=UTC))]
    slots = candidate_slots(rules, duration=timedelta(minutes=30), buffer=timedelta(minutes=10),
                            now=MONDAY, earliest=None, days=1, busy=busy)
    starts = [s[0].strftime("%H:%M") for s in slots]
    assert "06:00" not in starts and "06:30" not in starts and "07:00" not in starts
    assert "07:30" in starts


def test_min_notice_and_holidays():
    rules = BookingRules(min_notice_minutes=240, holidays=("2026-09-29",),
                         working_hours={"mon": [["06:00", "12:00"]], "tue": [["06:00", "12:00"]]})
    slots = candidate_slots(rules, duration=timedelta(minutes=60), buffer=timedelta(0),
                            now=MONDAY, earliest=None, days=3, busy=[])
    assert all(s[0] >= MONDAY + timedelta(hours=4) for s in slots)
    assert not any(s[0].date().isoformat() == "2026-09-29" for s in slots)


def test_spread_prefers_distinct_days():
    base = datetime(2026, 9, 28, 9, tzinfo=UTC)
    slots = [(base + timedelta(days=d, minutes=30 * i), base + timedelta(days=d, minutes=30 * i + 30))
             for d in range(3) for i in range(4)]
    chosen = spread(slots, 3)
    assert len({s[0].date() for s in chosen}) == 3


def test_display_is_localized_and_unknown_tz_rejected():
    assert "(America/New_York)" in display(MONDAY, "America/New_York")
    with pytest.raises(ValidationFailed):
        zone("Mars/Olympus")
