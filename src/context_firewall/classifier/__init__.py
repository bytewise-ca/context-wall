"""Intent Classifier — wraps context-compiler classification with CRE extensions."""

from context_firewall.classifier.classifier import classify_task, build_pipeline_context

__all__ = ["classify_task", "build_pipeline_context"]
