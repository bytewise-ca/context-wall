# Attack Reference — Context Injection Techniques

Technical deep-dive on the attack classes demonstrated in this demo.

---

## EchoLeak — CVE-2025-32711 (CVSS 9.3)

**Class:** Zero-click indirect prompt injection  
**Affected system:** Microsoft 365 Copilot  
**Disclosed:** June 2025

The first documented zero-click indirect prompt injection in a production enterprise LLM. An attacker sends a crafted email to a victim. Without any user interaction, Microsoft 365 Copilot processes the email, interprets embedded instructions as trusted directives, accesses internal SharePoint files, and exfiltrates them to attacker-controlled servers — all silently.

**Root cause:** Copilot's context window treats retrieved email content (untrusted, external) and system instructions (trusted, internal) identically. There is no trust-tier boundary between the two.

**CRE defence:** Source Trust Registry classifies email content as `external` or `untrusted` tier. The untrusted-source-sanitization policy blocks instruction-like patterns before they reach the model.

**Paper:** arXiv:2509.10540 — *EchoLeak: Stealing Private Information from Microsoft 365 Copilot via Indirect Prompt Injection*

---

## PoisonedRAG — USENIX Security 2025

**Class:** RAG corpus poisoning  
**Authors:** Zou et al., Carnegie Mellon University  
**Publication:** USENIX Security Symposium 2025

Demonstrates that adversarial documents injected into a RAG knowledge base can control LLM responses with 90%+ success rate — using only 5 crafted documents in a corpus of millions. The attack requires no model access, no jailbreak, and no system prompt modification. The LLM treats retrieved content as authoritative ground truth.

Three attack variants:
1. **Naive attack:** Simple false claims in retrieved documents
2. **Corpus poisoning:** Documents crafted to rank highly for target queries via embedding manipulation
3. **Conflict injection:** Documents that override correct answers by creating apparent consensus

**CRE defence:** Source trust tier is embedded in every retrieved artifact. Policy rules can gate `untrusted` sources from high-stakes task scopes (e.g., financial decisions, medical queries). The provenance trail records which documents influenced each response.

**Paper:** [USENIX Security 2025 — PoisonedRAG](https://www.usenix.org/system/files/usenixsecurity25-zou-poisonedrag.pdf)

---

## MINJA — NeurIPS 2025

**Class:** Agent memory poisoning via query-only interaction  
**Authors:** Hannecke et al.  
**Publication:** NeurIPS 2025

Demonstrates adversarial injection into an agent's persistent memory store through query-only interaction — no direct memory access required. Malicious records are planted via crafted queries that trigger memory writes. The attack achieves 95%+ injection success and is temporally decoupled: poison planted today executes weeks later when semantically triggered by a legitimate user query.

Unlike prompt injection (session-scoped), memory attacks survive across sessions. Standard defences that detect malicious actions fail because the agent's *beliefs* are corrupted before any anomalous action is taken.

**Attack surface in agentic systems:**
- Long-term memory stores (vector databases, episodic memory)
- Multi-turn conversation history
- Agent state files written between sessions

**CRE defence (Phase 2 roadmap):** RAG corpus integrity monitoring — continuous anomaly detection on document embedding drift, unusual retrieval patterns, and injection-pattern signatures in stored memories.

**Paper:** *Agent Memory Poisoning: The Attack That Waits* — NeurIPS 2025

---

## Indirect Prompt Injection — General Class

**OWASP Classification:** LLM01:2025 — Prompt Injection (top vulnerability for LLM applications)

The structural problem: LLM context windows make no distinction between trusted instructions (system prompt) and untrusted content (retrieved documents, tool outputs, web pages). Any content that enters the context window can contain instruction-like text that the model interprets as directives.

**Attack vectors in RAG systems:**
- Web search results containing embedded instructions
- PDFs and documents with instructions in footers, metadata, or hidden text
- API responses from third-party services
- User-submitted content processed alongside trusted data

**The CRE approach:** Instead of trying to detect injections in model output (after the fact), enforce trust-tier policy at the *context construction layer* — blocking instruction-like content from untrusted sources before the model ever processes it.
