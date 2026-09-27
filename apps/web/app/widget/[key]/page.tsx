"use client";

/**
 * Embeddable SAMIIR chat widget (served inside an iframe on approved sites only; the
 * frame-ancestors CSP is set per widget key by proxy.ts). All customer and model text is
 * rendered as React text nodes — never as HTML. Structured "cards" become components.
 */
import { useParams } from "next/navigation";
import * as React from "react";

type Card = { type: string; data: Record<string, unknown> };
type Msg = { id: string; sender: string; text: string; cards: Card[] };
type Slot = { n: number; display: string; slot_token: string };

async function call<T>(path: string, init: RequestInit & { json?: unknown } = {}, csrf?: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.json !== undefined) headers.set("Content-Type", "application/json");
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const res = await fetch(`/api/public${path}`, { ...init, headers, credentials: "same-origin",
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body, cache: "no-store" });
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) throw new Error(res.status === 429 ? "You're sending messages too quickly. Please wait a moment." :
    body?.error?.message ?? "Something went wrong. Please try again.");
  return body as T;
}

export default function Widget() {
  const { key } = useParams<{ key: string }>();
  const [csrf, setCsrf] = React.useState<string>();
  const [title, setTitle] = React.useState("Chat with us");
  const [messages, setMessages] = React.useState<Msg[]>([]);
  const [text, setText] = React.useState("");
  const [typing, setTyping] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [contact, setContact] = React.useState({ full_name: "", email: "", phone: "", consent_contact: false, consent_whatsapp: false });
  const honeypot = React.useRef<HTMLInputElement>(null);
  const end = React.useRef<HTMLDivElement>(null);
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

  React.useEffect(() => {
    call<{ csrf_token: string; greeting: string; tenant_name: string }>("/v1/widget/session", { method: "POST", json: { key } })
      .then(async (s) => {
        setCsrf(s.csrf_token);
        setTitle(s.tenant_name);
        const h = await call<{ messages: { id: string; sender: string; text: string; cards: Card[] }[] }>("/v1/widget/messages");
        setMessages(h.messages.length ? h.messages : [{ id: "greet", sender: "samiir", text: s.greeting, cards: [] }]);
      })
      .catch((e: Error) => setError(e.message));
  }, [key]);
  React.useEffect(() => end.current?.scrollIntoView({ behavior: "smooth" }), [messages, typing]);

  async function send(message: string, slotToken?: string) {
    if (!csrf || (!message.trim() && !slotToken)) return;
    setError(null);
    setMessages((m) => [...m, { id: crypto.randomUUID(), sender: "customer", text: message, cards: [] }]);
    setText("");
    setTyping(true);
    try {
      const r = await call<{ message_id: string; text: string; cards: Card[] }>("/v1/widget/messages", { method: "POST",
        json: { text: message || "(selected a time)", selected_slot_token: slotToken ?? null, timezone: tz,
                website: honeypot.current?.value || null } }, csrf);
      setMessages((m) => [...m, { id: r.message_id, sender: "samiir", text: r.text, cards: r.cards }]);
    } catch (e) { setError((e as Error).message); } finally { setTyping(false); }
  }

  async function submitContact(e: React.FormEvent) {
    e.preventDefault();
    if (!csrf) return;
    setTyping(true);
    try {
      const r = await call<{ message_id: string; text: string; cards: Card[] }>("/v1/widget/contact", { method: "POST",
        json: { ...contact, phone: contact.phone || null, website: honeypot.current?.value || null } }, csrf);
      setMessages((m) => [...m, { id: r.message_id, sender: "samiir", text: r.text, cards: r.cards }]);
    } catch (err) { setError((err as Error).message); } finally { setTyping(false); }
  }

  async function escalate() {
    if (!csrf) return;
    try {
      await call("/v1/widget/escalate", { method: "POST", json: {} }, csrf);
      setMessages((m) => [...m, { id: crypto.randomUUID(), sender: "system", text: "A member of our team has been notified and will join shortly.", cards: [] }]);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="flex h-screen flex-col bg-surface text-sm">
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div><p className="font-semibold">{title}</p><p className="text-xs text-muted">SAMIIR · AI assistant</p></div>
        <button onClick={() => void escalate()} className="text-xs underline">Talk to a person</button>
      </header>
      <div className="flex-1 space-y-3 overflow-y-auto p-4" aria-live="polite">
        {messages.map((m) => (
          <div key={m.id} className={m.sender === "customer" ? "ml-10 rounded-lg bg-accent p-3 text-accent-foreground" : "mr-10 rounded-lg border border-border bg-background p-3"}>
            <p className="whitespace-pre-wrap break-words">{m.text}</p>
            {m.cards.map((c, i) => <CardView key={i} card={c} onSlot={(s) => void send(`I'd like ${s.display}`, s.slot_token)} onQuick={(q) => void send(q)} />)}
            {m.cards.some((c) => c.type === "contact_form") ? (
              <form onSubmit={submitContact} className="mt-2 space-y-2">
                <input required maxLength={120} placeholder="Full name" aria-label="Full name" className="w-full rounded border border-border bg-surface px-2 py-1" value={contact.full_name} onChange={(e) => setContact({ ...contact, full_name: e.target.value })} />
                <input required type="email" maxLength={200} placeholder="Email" aria-label="Email" className="w-full rounded border border-border bg-surface px-2 py-1" value={contact.email} onChange={(e) => setContact({ ...contact, email: e.target.value })} />
                <input type="tel" maxLength={20} placeholder="Phone (optional, +country code)" aria-label="Phone" className="w-full rounded border border-border bg-surface px-2 py-1" value={contact.phone} onChange={(e) => setContact({ ...contact, phone: e.target.value })} />
                <label className="flex items-start gap-2 text-xs"><input type="checkbox" required checked={contact.consent_contact} onChange={(e) => setContact({ ...contact, consent_contact: e.target.checked })} />I agree that my details are stored to handle my request.</label>
                <label className="flex items-start gap-2 text-xs"><input type="checkbox" checked={contact.consent_whatsapp} onChange={(e) => setContact({ ...contact, consent_whatsapp: e.target.checked })} />Send me updates on WhatsApp.</label>
                <button className="rounded bg-accent px-3 py-1 text-accent-foreground">Share details</button>
              </form>
            ) : null}
          </div>
        ))}
        {typing ? <p className="text-xs text-muted">SAMIIR is typing…</p> : null}
        <div ref={end} />
      </div>
      {error ? <p role="alert" className="px-4 pb-1 text-xs text-critical">{error}</p> : null}
      <form onSubmit={(e) => { e.preventDefault(); void send(text); }} className="flex gap-2 border-t border-border p-3">
        {/* Honeypot for bots: hidden from people and assistive tech. */}
        <input ref={honeypot} name="website" tabIndex={-1} autoComplete="off" aria-hidden className="hidden" />
        <input value={text} maxLength={2000} onChange={(e) => setText(e.target.value)} placeholder="Type your message…"
               aria-label="Message" className="flex-1 rounded border border-border bg-surface px-3 py-2" />
        <button disabled={!csrf || typing || !text.trim()} className="rounded bg-accent px-4 text-accent-foreground disabled:opacity-50">Send</button>
      </form>
      <p className="px-3 pb-2 text-center text-[10px] text-subtle">AI assistant. Don't share passwords or payment details.</p>
    </div>
  );
}

function CardView({ card, onSlot, onQuick }: { card: Card; onSlot: (s: Slot) => void; onQuick: (q: string) => void }) {
  if (card.type === "slots") {
    const slots = (card.data.slots as Slot[]) ?? [];
    return <div className="mt-2 flex flex-col gap-1">{slots.map((s) => (
      <button key={s.slot_token} onClick={() => onSlot(s)} className="rounded border border-border px-2 py-1 text-left hover:bg-surface">{s.n}. {s.display}</button>))}</div>;
  }
  if (card.type === "quick_replies") {
    return <div className="mt-2 flex flex-wrap gap-1">{((card.data.options as string[]) ?? []).map((o) => (
      <button key={o} onClick={() => onQuick(o)} className="rounded-full border border-border px-2 py-0.5 text-xs">{o}</button>))}</div>;
  }
  if (card.type === "sources") {
    const src = (card.data.sources as { title: string; version: number }[]) ?? [];
    return <p className="mt-2 text-[11px] text-muted">Sources: {src.map((s) => `${s.title} (v${s.version})`).join("; ")}</p>;
  }
  if (card.type === "appointment") {
    return <p className="mt-2 text-xs font-medium">📅 {String(card.data.status)} {card.data.display ? `· ${String(card.data.display)}` : ""}</p>;
  }
  return null;
}
