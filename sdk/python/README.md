# contextwall-sdk (deprecated shim)

**As of ContextWall 0.2.0, the SDK ships inside the main [`contextwall`](https://pypi.org/project/contextwall/) package.**

This `contextwall-sdk` package is a thin deprecation shim that:

- Installs `contextwall>=0.2.0` (the main package)
- Re-exports everything from `context_firewall.sdk`
- Emits a `DeprecationWarning` on import so you know to migrate

The shim will be removed in v0.4.

## Migrate

```diff
- pip install contextwall-sdk[all]
+ pip install "contextwall[all]"
```

```diff
- from contextwall_sdk import SafeAnthropic
+ from context_firewall.sdk import SafeAnthropic
```

Nothing about the class or method contracts changed — only the import path.

## Full docs

See [contextwall on PyPI](https://pypi.org/project/contextwall/) or the
[GitHub repo](https://github.com/bytewise-ca/context-wall).
