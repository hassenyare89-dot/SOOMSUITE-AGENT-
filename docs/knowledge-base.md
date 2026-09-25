# Knowledge base (SAMIIR)

SAMIIR answers **only** from approved knowledge and structured tool data. A document the model
has not retrieved from the approved set is, for SAMIIR, unknown.

## Lifecycle

```
DRAFT ──submit──► PENDING_APPROVAL ──approve (knowledge.approve)──► APPROVED ──archive──► ARCHIVED
  ▲                      │                                              │
  └──────────── edit (creates a new version, back to DRAFT) ◄───────────┘
```

- Every edit creates a new version. Only the `APPROVED` version is chunked, embedded and searchable.
- Approval requires `knowledge.approve`. With `require_distinct_approver` (default) the author
  cannot approve their own document.
- Archiving removes chunks from retrieval immediately.
- All transitions are audited.

## Categories

`company_profile`, `services`, `pricing`, `faq`, `policies`, `security_services`,
`appointment_info`, `contact`. Use the `pricing` category with **structured items** for anything
priced. Prose prices are never quoted.

### Structured pricing format

```json
{
  "title": "Managed SOC pricing",
  "category": "pricing",
  "body": "Human-readable description…",
  "structured": {
    "currency": "USD",
    "items": [
      {"name": "Managed SOC – Starter", "price": 1500, "unit": "month",
       "notes": "Up to 50 assets", "valid_until": "2027-06-30"}
    ]
  }
}
```

`get_pricing` returns only items from approved pricing documents, ranked by word overlap with
the question. If nothing matches, SAMIIR offers to connect the visitor with sales.

## Retrieval

- Chunking: paragraph-aware, 900 characters with 150 overlap (configurable), per approved version.
- Embeddings: `text-embedding-3-small` (1536 dims) in pgvector with an HNSW index. The offline
  `HashingEmbedder` fallback (with stopword filtering) is for development and tests only.
- Search is tenant-scoped by RLS, filtered to `APPROVED`, and has a minimum similarity threshold.
- Results reach the model wrapped as untrusted reference data. Instructions inside documents
  are not followed.

## Grounding guardrail

Before any SAMIIR reply leaves the service, the output guardrail extracts:
- money amounts and currencies, percentages and discounts,
- clock times and dates,
- commitments ("we guarantee", "free", "refund", "SLA"),

and requires each to appear in this turn's tool outputs. If any value is unsupported, the reply
is replaced with a safe answer that offers a human follow-up, and the event is audited.

## Authoring guidance
- Write facts, not instructions to the assistant.
- Keep one topic per document so it retrieves cleanly.
- Put prices, discounts and SLAs in structured data with `valid_until`.
- Security services are described for sales purposes only. Any request to scan or test is routed
  to a *security review* appointment, never to FATMA.
