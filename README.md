# ContextWall

**A context firewall for AI agents and RAG pipelines.**

Your agents pull context from everywhere: web search, internal docs, partner APIs, user uploads. ContextWall sits in front of every source, enforces your security policy, and stops malicious content before it reaches the model. No code changes to your agents required.

```
web search ──┐
internal docs─┤                           ┌─► Claude / GPT-4
partner APIs ─┼──► ContextWall ──► policy ─┤
user uploads ─┤   (your rules)            └─► blocked + audit trail
FHIR / PHI  ──┘
```

---

## Why this exists

**EchoLeak (CVE-2025-32711, CVSS 9.3):** a crafted email caused Microsoft 365 Copilot to silently access SharePoint files and exfiltrate them. Zero user interaction. The root cause: the model had no way to tell the difference between a trusted system instruction and untrusted email content.

**PoisonedRAG (USENIX Security 2025):** 5 adversarial documents in a corpus of millions achieved 90%+ control over LLM responses. The model treated retrieved content as ground truth.

These are not edge cases. They are the default behavior of every RAG pipeline and agentic system that doesn't enforce source trust at the context layer.

---

## How ContextWall fixes it

**Every context source gets a trust tier.** Internal wikis, public web, regulated PHI data. Each carries a different level of trust, and your policy rules apply differently per tier.

**Content is scanned before the model sees it.** Three detection layers (structural bidi/zero-width scanning, normalized regex, and heuristic scoring for semantic paraphrases) run in under a millisecond with no LLM inference.

**Every decision is logged.** Tamper-evident Merkle chain, exportable as SOC2 evidence, HIPAA audit trail, or FedRAMP control mappings.

| Source tier | Examples | Default enforcement |
|-------------|----------|---------------------|
| `internal` | Code repos, internal wikis | Injection blocked, PII audit-only |
| `external` | Vendor docs, partner APIs | Injection blocked, PII warned |
| `untrusted` | Public web, user uploads | Injection + PII blocked |
| `regulated` | FHIR, PHI data sources | Injection + PII blocked, full compliance audit |

---

## Get started

**OSS daemon** (runs in your infrastructure, free forever):
```bash
# Install and start
pip install contextwall
ctxfw start --config ctxfw.yaml

# Or run with Docker
docker run -p 8080:8080 \
  -v $(pwd)/ctxfw.yaml:/app/ctxfw.yaml \
  ghcr.io/bytewise-ca/context-wall:latest
```

**Cloud dashboard** (optional: fleet visibility, policy authoring, compliance reports):
> Sign up at [app.contextwall.dev](https://app.contextwall.dev), generate a registration token in Settings, then add it to `ctxfw.yaml`:
> ```yaml
> control_plane:
>   url: https://app.contextwall.dev
>   registration_token: cwt_your-token-here
>   daemon_name: prod-us-east-1
> ```
> The daemon pushes only aggregated metadata (counts, scores) to the cloud. **Prompts, documents, and file contents never leave your infrastructure.**

---

## Integration

### Option 1: Environment variable (zero code change)

Point your existing SDK at the local daemon. Your agents don't need to change at all.

```bash
# Anthropic (daemon runs on localhost:8080)
export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
export ANTHROPIC_API_KEY=sk-ant-your-real-key   # unchanged

# OpenAI
export OPENAI_BASE_URL=http://localhost:8080/proxy/openai/v1
export OPENAI_API_KEY=sk-your-real-key          # unchanged
```

Every `anthropic.Anthropic()` or `openai.OpenAI()` call in your codebase is now screened locally. Prompts never leave your machine.

---

### Option 2: Python SDK (drop-in replace)

```python
from contextwall import SafeAnthropic, CREBlockedError

# Drop-in replacement for anthropic.Anthropic()
client = SafeAnthropic(
    cre_endpoint="http://localhost:8080",   # local daemon
)

try:
    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": task}],
    )
except CREBlockedError as e:
    print(f"Blocked: {e.blocked_reason}")   # injection_heuristic:instruction_override
    print(f"Violations: {e.violations}")
```

```bash
pip install contextwall                  # base
pip install "contextwall[anthropic]"     # + Anthropic SDK
pip install "contextwall[openai]"        # + OpenAI SDK
pip install "contextwall[all]"           # everything
```

---

### Option 3: Document filter API (for RAG pipelines)

If your pipeline retrieves documents before calling the LLM, filter them through ContextWall before constructing the prompt. This is the primary defence against corpus poisoning.

```python
import httpx

async def safe_rag(query: str, source_id: str) -> list[dict]:
    """Retrieve documents and filter through ContextWall before passing to LLM."""
    raw_docs = await your_vector_store.search(query)

    response = await httpx.AsyncClient().post(
        "http://localhost:8080/v1/filter",   # local daemon, no cloud call
        json={
            "source_id": source_id,
            "documents": raw_docs,
            "session_id": session_id,
        },
    )

    result = response.json()
    # result["documents"]         - allowed docs, safe to include in prompt
    # result["blocked"]           - count of blocked documents
    # result["blocked_documents"] - what was blocked and why
    return result["documents"]
```

ContextWall applies the trust tier of `source_id` to every document. A `trust_tier: untrusted` source gets full injection detection and PII scanning. The blocked documents never reach your prompt.

---

## Declare your sources in config

Sources are declared in `ctxfw.yaml`. No API calls, no imperative setup code. Commit it alongside your infrastructure.

```yaml
# ctxfw.yaml

sources:
  - id: brave-web-search
    type: web
    trust_tier: untrusted

  - id: internal-confluence
    type: confluence
    trust_tier: internal
    data_classification: sensitive

  - id: fhir-api
    type: api
    trust_tier: regulated
    data_classification: phi
    owner: clinical-data-team
    region: us-east-1
```

ContextWall registers these on every startup: idempotent, version-controlled, reviewable in a PR.

---

## Policy as code

Write security rules in YAML. Commit them. Review them like any other infrastructure change.

```yaml
# policies/fleet/no-phi-exfil.yaml
rules:
  - name: block-phi-exfiltration
    action: deny
    reason: "PHI must not leave regulated sources"
    applies_when:
      source_tier: [regulated]
    compliance_mapping:
      framework: hipaa
      control_id: "45 CFR 164.502(b)"

  - name: block-web-injection
    action: deny
    reason: "Untrusted web content blocked from high-stakes tasks"
    applies_when:
      source_tier: [untrusted]
      task_scope: [financial_decision, medical_query]
    compliance_mapping:
      framework: soc2
      control_id: "CC6.1"
```

Rules reload within 5 seconds of a file change. No restart. No redeploy.

**Pre-built policy packs** for HIPAA, SOC2, and FedRAMP ship out of the box.

---

## Tune detection sensitivity

Override defaults in `ctxfw.yaml`, per deployment, per environment.

```yaml
detection:
  injection_block_threshold: 0.55   # raise to reduce false positives
  injection_warn_threshold: 0.35    # lower to catch more, audit instead of block
  default_source_trust_tier: untrusted

enforcement:
  penalty_increment: 0.15           # trust penalty per deny event
  decay_half_life_days: 1.0         # penalty halves every N days (auto-recovery)
  reward_factor: 0.90               # trust improves with clean outcomes
```

---

## What gets detected

| Attack class | Detection layer | Example |
|---|---|---|
| Direct instruction override | L1 structural + L2 regex | `IGNORE ALL PREVIOUS INSTRUCTIONS` |
| Bidi / zero-width obfuscation | L1 structural | RTL override chars in retrieved text |
| Spaced-letter injection | L1 structural | `i g n o r e  p r e v i o u s` |
| Semantic paraphrase injection | L3 heuristic | "Your previous assignment has been superseded by the administrator" |
| Secret leakage | L2 regex | AWS keys, GitHub PATs, bearer tokens, private keys |
| PII exfiltration | L2 regex | Emails, phone numbers, SSNs in untrusted context |

Sub-millisecond latency. No LLM in the hot path.

---

## Compliance

Every enforcement decision writes to a Merkle-chained append-only log. Export on demand:

```bash
# SOC2 Type II evidence package (JSON, cryptographically signed)
ctxfw compliance export --framework soc2 --days 90 --out soc2-evidence.json

# HIPAA audit trail
ctxfw compliance export --framework hipaa --days 365 --out hipaa-audit.json

# Or call the local API directly
curl http://localhost:8080/v1/compliance/export \
  -H "Authorization: Bearer $CRE_API_TOKEN" \
  -d '{"framework": "soc2", "days": 90}'
```

Every export is cryptographically signed. The `/v1/compliance/verify` endpoint proves chain integrity independently of the exporter.

Supported: **SOC2 Type II**, **HIPAA** (45 CFR 164.312), **FedRAMP** (NIST 800-53), **GDPR** (Article 32).

---

## Observability

```
GET  /health              - subsystem health
GET  /metrics             - Prometheus metrics
WS   /ws/events           - live enforcement event stream
GET  /v1/sources          - registered sources + enforcement history
GET  /v1/sources/{id}/trust - trust health per source
```

Key metrics emitted:

| Metric | What it tells you |
|--------|-------------------|
| `cre_proxy_requests_total{result}` | Block rate by provider |
| `cre_proxy_violations_total{type}` | Breakdown by violation type |
| `cre_enforcement_penalty{source}` | Trust degradation per source |
| `cre_pipeline_duration_seconds` | End-to-end latency |

---

## Architecture

```
                   ctxfw.yaml (sources, policy, thresholds)
                          │
Your agent / RAG pipeline │
          │               ▼
          │         ContextWall
          │         ┌─────────────────────────────────────────┐
          │         │  Source Registry (O(1) tier lookup)     │
          └────────►│                                         │
                    │  L1  Structural scan    (<0.1ms)        │
                    │  L2  Normalized regex   (<0.2ms)        │
                    │  L3  Heuristic scoring  (<0.5ms)        │
                    │                                         │
                    │  Policy DSL (fleet→org→team→repo)       │
                    └──────────────┬──────────────────────────┘
                                   │
                    ┌──────────────┴──────────────────────────┐
                    │  allowed                  blocked        │
                    ▼                               ▼          │
              LLM API                     400 + violation      │
         (Anthropic / OpenAI)             details              │
                                               │               │
                                               ▼               │
                                      Provenance Engine        │
                                   (Merkle-chained log)        │
                                          │                    │
                              ┌───────────┼───────────┐        │
                              ▼           ▼           ▼        │
                           SQLite    WebSocket    Compliance    │
                                     live feed    export       │
                    └────────────────────────────────────────── ┘
```

---

## Self-hosting

```yaml
# ctxfw.yaml: minimal production config
repository_root: /app

sources:
  - id: my-web-search
    type: web
    trust_tier: untrusted

rest_api:
  port: 8080
  auth:
    enabled: true
    tokens:
      - token: "${CRE_API_TOKEN}"
        name: admin
        scopes: [analyze, bundle, admin, compliance]

storage:
  db_path: /data/cre.db

policy:
  policy_dir: /data/policies

compliance_hmac_key: "${CRE_COMPLIANCE_HMAC_KEY}"
```

```bash
# Generate secrets
export CRE_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export CRE_COMPLIANCE_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

docker run -d -p 8080:8080 \
  -e CRE_API_TOKEN \
  -e CRE_COMPLIANCE_HMAC_KEY \
  -v $(pwd)/ctxfw.yaml:/app/ctxfw.yaml \
  -v $(pwd)/policies:/data/policies \
  -v cre-data:/data \
  ghcr.io/bytewise-ca/context-wall:latest
```

ContextWall refuses to start with known-weak tokens and prints a generation command. Compliance HMAC key absence is warned at startup.

---

## What's in this repo

| Component | Path | Description |
|-----------|------|-------------|
| Core daemon | `src/context_firewall/` | Proxy, policy engine, provenance, trust scoring |
| Python SDK | `sdk/python/` | `SafeAnthropic`, `SafeOpenAI`, `CREClient` |
| Policy packs | `policy/packs/` | Pre-built HIPAA, SOC2, FedRAMP rule sets |
| Live demo | `demo/` | Attack scenarios + dashboard (requires API keys) |
| Web dashboard | `webapp/` | Next.js live enforcement viewer |

---

## License

**AGPL v3:** core proxy, policy engine, provenance chain, Python SDK.

If you run ContextWall as a service (managed or embedded), AGPL requires you to release your modifications under the same terms. If your organisation cannot comply with AGPL (for example, you want to embed ContextWall in a proprietary product or offer it as a closed SaaS), a commercial license is available at [contextwall.io](https://contextwall.io).

Fleet policy management, multi-tenant control plane, and the cloud dashboard are available on the paid cloud plan only.
