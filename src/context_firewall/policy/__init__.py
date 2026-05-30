"""Policy Engine — multi-layer detection and access control."""

__all__ = ["PolicyEngine"]


def __getattr__(name: str):
    if name == "PolicyEngine":
        from context_firewall.policy.engine import PolicyEngine
        return PolicyEngine
    raise AttributeError(name)
