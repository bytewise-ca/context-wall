# contextwall-sdk

Drop-in wrapper for Anthropic and OpenAI that routes calls through a local [ContextWall](https://contextwall.io) daemon, enforcing your context firewall policy with no other code changes.

## Install

```bash
pip install 'contextwall-sdk[anthropic]'
pip install 'contextwall-sdk[openai]'
pip install 'contextwall-sdk[all]'
```

## Usage

```python
from contextwall_sdk import SafeAnthropic

client = SafeAnthropic(api_key="sk-ant-...", ctxfw_url="http://localhost:8080")
# use exactly like the standard Anthropic client
```

```python
from contextwall_sdk import SafeOpenAI

client = SafeOpenAI(api_key="sk-...", ctxfw_url="http://localhost:8080")
```

Blocked requests raise `contextwall_sdk.ContextWallBlockedError` with the policy violation detail.

## Daemon setup

The SDK requires a running ContextWall daemon. See the [quickstart](https://contextwall.io/quickstart) or the [GitHub repo](https://github.com/bytewise-ca/context-wall).
