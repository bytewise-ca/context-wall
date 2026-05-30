"""Intent Classifier implementation."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime

from context_firewall.config import Config
from context_firewall.models import (
    ClassificationResult,
    PipelineContext,
    TaskType,
    TraversalStrategy,
)

logger = logging.getLogger(__name__)

_SECURITY_REVIEW_KEYWORDS = frozenset([
    "security", "audit", "vulnerability", "cve", "exploit", "injection",
    "xss", "csrf", "auth", "authentication", "authorization", "permission",
    "sanitize", "validate input", "secret", "credential", "token leak",
])

_DEPENDENCY_AUDIT_KEYWORDS = frozenset([
    "dependency", "dependencies", "package", "import", "require",
    "go.mod", "package.json", "requirements.txt", "sbom", "supply chain",
    "license", "outdated", "upgrade package",
])

_AUGMENTED_KEYWORDS: dict[TaskType, list[str]] = {
    TaskType.SECURITY_REVIEW: [
        "auth", "middleware", "token", "session", "permission", "sanitize", "validate",
    ],
    TaskType.DEPENDENCY_AUDIT: [
        "import", "require", "go.mod", "package.json", "requirements.txt", "sbom",
    ],
}

_TRAVERSAL_STRATEGIES: dict[TaskType, TraversalStrategy] = {
    TaskType.BUG_FIX: TraversalStrategy(
        edge_types=["calls", "imports"],
        direction="both",
        max_depth=4,
    ),
    TaskType.NEW_FEATURE: TraversalStrategy(
        edge_types=["calls", "imports", "inherits"],
        direction="both",
        max_depth=4,
    ),
    TaskType.REFACTOR: TraversalStrategy(
        edge_types=["calls", "imports", "inherits", "implements"],
        direction="both",
        max_depth=4,
    ),
    TaskType.SECURITY_REVIEW: TraversalStrategy(
        edge_types=["calls", "imports", "uses"],
        direction="inbound",
        max_depth=3,
    ),
    TaskType.DEPENDENCY_AUDIT: TraversalStrategy(
        edge_types=["imports", "requires"],
        direction="outbound",
        max_depth=2,
    ),
}

_WEIGHT_PROFILES: dict[TaskType, str] = {
    TaskType.BUG_FIX: "bug_fix",
    TaskType.NEW_FEATURE: "new_feature",
    TaskType.REFACTOR: "refactor",
    TaskType.SECURITY_REVIEW: "security_review",
    TaskType.DEPENDENCY_AUDIT: "dependency_audit",
}


def _detect_cre_extension(task: str) -> TaskType | None:
    lower = task.lower()
    security_hits = sum(1 for kw in _SECURITY_REVIEW_KEYWORDS if kw in lower)
    dependency_hits = sum(1 for kw in _DEPENDENCY_AUDIT_KEYWORDS if kw in lower)
    if security_hits >= 2:
        return TaskType.SECURITY_REVIEW
    if dependency_hits >= 2:
        return TaskType.DEPENDENCY_AUDIT
    return None


def _classify_via_context_compiler(task: str) -> ClassificationResult:
    try:
        from context_compiler.retrieval.classifier import classify, extract_query_keywords
        from context_compiler.models import TaskType as CCTaskType

        cc_task_type = classify(task)
        keywords = extract_query_keywords(task)
        task_type_map = {
            "BUG_FIX": TaskType.BUG_FIX,
            "NEW_FEATURE": TaskType.NEW_FEATURE,
            "REFACTOR": TaskType.REFACTOR,
        }
        task_type = task_type_map.get(cc_task_type.value, TaskType.NEW_FEATURE)
        return ClassificationResult(
            task_type=task_type,
            confidence=1.0,
            keywords=list(keywords),
            source="context-compiler",
        )
    except Exception as e:
        logger.warning("context-compiler classify failed, using fallback", extra={"error": str(e)})
        return ClassificationResult(
            task_type=TaskType.NEW_FEATURE,
            confidence=0.0,
            keywords=[],
            source="fallback",
        )


def classify_task(task: str) -> ClassificationResult:
    t0 = time.monotonic()

    cre_type = _detect_cre_extension(task)
    if cre_type is not None:
        augmented = _AUGMENTED_KEYWORDS.get(cre_type, [])
        result = ClassificationResult(
            task_type=cre_type,
            confidence=1.0,
            keywords=augmented,
            source="cre-extension",
        )
    else:
        result = _classify_via_context_compiler(task)
        augmented = _AUGMENTED_KEYWORDS.get(result.task_type, [])
        if augmented:
            result = result.model_copy(update={"keywords": result.keywords + augmented})

    elapsed_ms = (time.monotonic() - t0) * 1000
    logger.debug("classify_task", extra={"task_type": result.task_type, "latency_ms": elapsed_ms})
    return result


def build_pipeline_context(
    task: str,
    classification: ClassificationResult,
    session_id: str,
    config: Config,
) -> PipelineContext:
    strategy = _TRAVERSAL_STRATEGIES.get(
        classification.task_type,
        TraversalStrategy(edge_types=["calls", "imports"], direction="both", max_depth=4),
    )
    # respect config depth override
    if config.graph.max_depth != 4:
        strategy = strategy.model_copy(update={"max_depth": config.graph.max_depth})

    return PipelineContext(
        task=task,
        task_type=classification.task_type,
        confidence=classification.confidence,
        keywords=classification.keywords,
        traversal_strategy=strategy,
        trust_weight_profile=_WEIGHT_PROFILES.get(classification.task_type, "new_feature"),
        request_id=str(uuid.uuid4()),
        session_id=session_id,
        received_at=datetime.utcnow(),
    )
