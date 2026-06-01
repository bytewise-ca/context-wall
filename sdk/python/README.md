# contextwall-sdk

Drop-in context firewall enforcement for any LLM. Routes calls through a local [ContextWall](https://contextwall.io) daemon, enforcing your policy before content reaches the model.

Built-in wrappers for Anthropic and OpenAI. Any OpenAI-compatible API (Mistral, Groq, Together, Ollama, etc.) works via `SafeOpenAI`. For other providers, use the zero-code proxy mode.

## Install

```bash
pip install 'contextwall-sdk[anthropic]'   # Anthropic
pip install 'contextwall-sdk[openai]'      # OpenAI + any OpenAI-compatible API
pip install 'contextwall-sdk[all]'         # both
```

## Usage

**Anthropic:**
```python
from contextwall_sdk import SafeAnthropic, ContextWallBlockedError

client = SafeAnthropic(api_key="sk-ant-...", ctxfw_url="http://localhost:8080")
# use exactly like the standard Anthropic client
```

**OpenAI / any OpenAI-compatible API:**
```python
from contextwall_sdk import SafeOpenAI

# OpenAI
client = SafeOpenAI(api_key="sk-...", ctxfw_url="http://localhost:8080")

# Mistral, Groq, Together, Ollama — just pass base_url
client = SafeOpenAI(api_key="...", ctxfw_url="http://localhost:8080",
                    base_url="https://api.mistral.ai/v1")
```

**Zero-code proxy mode (any provider, no SDK changes):**
```bash
export ANTHROPIC_BASE_URL=http://localhost:8080/proxy/anthropic
export OPENAI_BASE_URL=http://localhost:8080/proxy/openai
# your existing code runs unchanged
```

Blocked requests raise `ContextWallBlockedError` with the policy violation detail.

## Daemon setup

Requires a running ContextWall daemon. See the [quickstart](https://contextwall.io/quickstart) or the [GitHub repo](https://github.com/bytewise-ca/context-wall).
