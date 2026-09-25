"""Rule-based runtime used without a model API key (local development, CI, degraded mode).

It exercises exactly the same tool gateway, policy checks and grounding as the LLM runtime,
which keeps the security properties testable without network access."""

from __future__ import annotations

import re

from platform_core.schemas.chat import Card
from samiir_agent.guardrails import SAFE_FALLBACK
from samiir_agent.runtime import AgentResult
from samiir_agent.tools import RunState, ToolGateway

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"\+?[1-9]\d{6,14}")
NAME = re.compile(r"(?:my name is|i am|i'm|this is)\s+([A-Z][a-zA-Z'-]+(?:\s[A-Z][a-zA-Z'-]+)?)")
SLOT_CHOICE = re.compile(r"\b(?:slot|option|number|#)\s*([1-5])\b|^\s*([1-5])\s*$", re.I)
ORDINALS = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5}

INTENTS: list[tuple[str, re.Pattern[str]]] = [
    ("human", re.compile(r"\b(human|real person|agent|representative|someone|talk to|speak to|"
                         r"complain|complaint|refund|lawyer|legal)\b", re.I)),
    ("cancel", re.compile(r"\bcancel\b", re.I)),
    ("reschedule", re.compile(r"\b(reschedule|move my|change (?:the|my) (?:time|appointment))\b",
                              re.I)),
    ("book", re.compile(r"\b(book|appointment|schedule|meeting|call|demo|consultation|"
                        r"available|availability)\b", re.I)),
    ("pricing", re.compile(r"\b(price|pricing|cost|how much|fee|rate|quote)\b", re.I)),
    ("greeting", re.compile(r"^\s*(hi|hello|hey|salaam|good (?:morning|afternoon|evening))\b",
                            re.I)),
]


class DeterministicRuntime:
    name = "deterministic"

    async def run(self, gateway: ToolGateway, state: RunState, history: list[dict[str, str]],
                  message: str, company_name: str) -> AgentResult:
        text = await self._respond(gateway, state, message, company_name)
        return AgentResult(text=text, model=None)

    async def _respond(self, gw: ToolGateway, st: RunState, msg: str, company: str) -> str:
        email, phone = EMAIL.search(msg), PHONE.search(msg.replace(" ", ""))
        name = NAME.search(msg)
        if email or phone:
            result = await gw.invoke(st, "crm.capture_contact", {
                "full_name": name.group(1) if name else None,
                "email": email.group(0) if email else None,
                "phone": phone.group(0) if phone and not email else None,
                "company_name": None, "customer_agreed_to_share": True,
                "whatsapp_updates_opt_in": False})
            if result.startswith("SAVED"):
                if token := st.context.get("pending_slot_token"):
                    display = next((o["display"] for o in st.context.get("offered_slots", [])
                                    if o["token"] == token), "your selected time")
                    booked = await gw.invoke(st, "calendar.book_appointment", {
                        "slot_number": next((o["n"] for o in st.context.get("offered_slots", [])
                                             if o["token"] == token), 1)})
                    if booked.startswith("BOOKED"):
                        return f"Thank you! Your appointment is confirmed for {display}."
                return ("Thank you, I've saved your details. How can I help you further — would "
                        "you like to book a consultation?")
            return "I couldn't save those details. Could you double-check them?"

        if st.context.get("offered_slots"):
            choice = SLOT_CHOICE.search(msg)
            n = int(choice.group(1) or choice.group(2)) if choice else next(
                (v for k, v in ORDINALS.items() if re.search(rf"\b{k}\b", msg, re.I)), None)
            if n:
                tool = ("calendar.reschedule_appointment"
                        if st.context.get("reschedule_pending") else "calendar.book_appointment")
                result = await gw.invoke(st, tool, {"slot_number": n})
                st.context.pop("reschedule_pending", None)
                if result.startswith(("BOOKED", "RESCHEDULED")):
                    return result.split(": ", 1)[1]
                if result.startswith("NEED_CONTACT"):
                    return ("Great choice! To confirm the booking, please share your name and "
                            "email address.")
                return "Sorry, I couldn't book that slot. Would you like me to check other times?"

        intent = next((name for name, pat in INTENTS if pat.search(msg)), "question")
        if intent == "human":
            await gw.invoke(st, "conversation.escalate_to_human", {"reason": "customer request"})
            return "Of course — I've asked a member of our team to join this conversation."
        if intent == "cancel":
            result = await gw.invoke(st, "calendar.cancel_appointment",
                                     {"reason": "customer request"})
            return ("Your appointment has been cancelled." if result.startswith("CANCELLED")
                    else "I couldn't find an appointment booked in this conversation.")
        if intent in ("book", "reschedule"):
            result = await gw.invoke(st, "calendar.check_availability",
                                     {"appointment_type": None, "earliest_date": None})
            if not result.startswith("AVAILABLE_SLOTS"):
                return ("I couldn't find available times right now. I can ask a team member to "
                        "contact you — would that help?")
            if intent == "reschedule":
                st.context["reschedule_pending"] = True
            slots = "\n".join(f"{o['n']}. {o['display']}" for o in st.context["offered_slots"])
            return f"Here are the next available times:\n{slots}\nWhich one works for you?"
        if intent == "pricing":
            result = await gw.invoke(st, "pricing.lookup", {"service": _topic(msg)})
            if result.startswith("APPROVED_PRICING"):
                lines = result.split("\n", 1)[1]
                return f"Here is our current approved pricing:\n{lines}"
            result = await gw.invoke(st, "pricing.lookup", {"service": None})
            if result.startswith("APPROVED_PRICING"):
                return ("I don't have a listed price for exactly that, but here is our approved "
                        "pricing:\n" + result.split("\n", 1)[1])
            await gw.invoke(st, "conversation.escalate_to_human", {"reason": "pricing request"})
            return ("I don't have approved pricing for that yet, so I've asked our sales team to "
                    "follow up with an accurate quote.")
        if intent == "greeting" and len(msg) < 40:
            st.cards.append(Card(type="quick_replies", data={"options": [
                "What services do you offer?", "Pricing", "Book a consultation",
                "Talk to a person"]}))
            return f"Hello! I'm SAMIIR, {company}'s assistant. How can I help you today?"
        result = await gw.invoke(st, "knowledge.search", {"query": msg[:300], "category": None})
        if result.startswith("NO_APPROVED") or result.startswith("ERROR"):
            await gw.invoke(st, "conversation.escalate_to_human", {"reason": "no approved answer"})
            return SAFE_FALLBACK
        return _summarize(st.grounding[0] if st.grounding else "")


def _topic(msg: str) -> str | None:
    words = [w for w in re.findall(r"[a-zA-Z]{4,}", msg)
             if w.lower() not in {"price", "pricing", "cost", "much", "does", "your", "what",
                                  "quote", "would", "like", "know", "please", "about", "rate"}]
    return " ".join(words[:4]) or None


def _summarize(chunk: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", chunk.strip())
    body = " ".join(sentences[:3]).strip()
    return body if body else SAFE_FALLBACK
