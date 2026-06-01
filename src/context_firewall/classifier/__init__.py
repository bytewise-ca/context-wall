"""Intent Classifier - wraps context-compiler classification with ContextWall extensions."""

from context_firewall.classifier.classifier import classify_task, build_pipeline_context

__all__ = ["classify_task", "build_pipeline_context"]
