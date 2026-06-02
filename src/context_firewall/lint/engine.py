"""Lint engine - audits provenance and policy data for anomalies.

Inspired by the Karpathy LLM Wiki pattern: use existing logged data to
surface contradictions, drift, and orphans that operators would miss by
looking at individual events. Runs offline (APScheduler), never in hot path.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from context_firewall.db.connection import get_db

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"error": 3, "warn": 2, "info": 1}


@dataclass
class LintFinding:
    category: str        # orphan_session | tier_drift | stale_rule | contradiction
    severity: str        # error | warn | info
    subject: str         # session_id, project_id, rule_name, pattern_name
    detail: str
    suggestion: str


@dataclass
class LintReport:
    ran_at: str
    window_days: int
    findings: list[LintFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def add(self, finding: LintFinding) -> None:
        self.findings.append(finding)
        self.summary[finding.severity] = self.summary.get(finding.severity, 0) + 1
        self.summary[finding.category] = self.summary.get(finding.category, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "ran_at": self.ran_at,
            "window_days": self.window_days,
            "summary": self.summary,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "subject": f.subject,
                    "detail": f.detail,
                    "suggestion": f.suggestion,
                }
                for f in sorted(
                    self.findings,
                    key=lambda x: (-_SEVERITY_RANK.get(x.severity, 0), x.category),
                )
            ],
        }


class LintEngine:
    name = "lint_engine"
    critical = False

    def __init__(self) -> None:
        self._ready = False

    async def init(self, config: Any) -> None:
        self._ready = True

    def health_check(self):
        from context_firewall.models import SubsystemHealth
        return SubsystemHealth(name=self.name, healthy=self._ready)

    async def shutdown(self) -> None:
        pass

    async def run(self, window_days: int = 30) -> LintReport:
        report = LintReport(
            ran_at=datetime.now(timezone.utc).isoformat(),
            window_days=window_days,
        )
        db = await get_db()
        await self._check_orphan_sessions(db, report, window_days)
        await self._check_tier_drift(db, report, window_days)
        await self._check_stale_rules(db, report, window_days)
        await self._check_contradictions(db, report, window_days)

        await self._persist(report)
        logger.info(
            "lint complete: %d findings (%s)",
            len(report.findings),
            ", ".join(f"{k}={v}" for k, v in report.summary.items()),
        )
        return report

    # ── Individual checks ─────────────────────────────────────────────────────

    async def _check_orphan_sessions(
        self, db, report: LintReport, window_days: int
    ) -> None:
        """Sessions with proxy activity but no recorded outcomes, older than 24h."""
        try:
            async with db.execute("""
                SELECT
                    pe.session_id,
                    COUNT(pe.id) AS event_count,
                    MAX(pe.occurred_at) AS last_event
                FROM provenance_events pe
                LEFT JOIN outcome_signals os ON pe.session_id = os.session_id
                WHERE
                    os.session_id IS NULL
                    AND pe.occurred_at < datetime('now', '-1 day')
                    AND pe.occurred_at > datetime('now', :window)
                GROUP BY pe.session_id
                HAVING event_count > 0
                ORDER BY event_count DESC
                LIMIT 50
            """, {":window": f"-{window_days} days"}) as cur:
                rows = await cur.fetchall()

            for row in rows:
                report.add(LintFinding(
                    category="orphan_session",
                    severity="info",
                    subject=row["session_id"] or "unknown",
                    detail=f"{row['event_count']} events, last seen {row['last_event']}",
                    suggestion="Record an outcome via POST /v1/outcome or investigate if the agent crashed.",
                ))
        except Exception as e:
            logger.debug("orphan session check skipped: %s", e)

    async def _check_tier_drift(
        self, db, report: LintReport, window_days: int
    ) -> None:
        """Sources whose proxy block rate exceeds 30% - may warrant a trust tier downgrade."""
        try:
            async with db.execute("""
                SELECT
                    reason,
                    action,
                    occurred_at
                FROM provenance_events
                WHERE
                    event_type = 'enforcement'
                    AND occurred_at > datetime('now', :window)
                    AND reason LIKE '%project=%'
            """, {":window": f"-{window_days} days"}) as cur:
                rows = await cur.fetchall()

            project_total: dict[str, int] = {}
            project_blocked: dict[str, int] = {}
            project_tier: dict[str, str] = {}

            for row in rows:
                reason = row["reason"] or ""
                m = re.search(r"project=(\S+)", reason)
                if not m:
                    continue
                project = m.group(1)
                tier_m = re.search(r"tier=(\S+)", reason)
                tier = tier_m.group(1) if tier_m else "unknown"

                project_total[project] = project_total.get(project, 0) + 1
                project_tier[project] = tier
                if row["action"] in ("deny", "block", "exclude"):
                    project_blocked[project] = project_blocked.get(project, 0) + 1

            for project, total in project_total.items():
                if total < 5:
                    continue
                blocked = project_blocked.get(project, 0)
                rate = blocked / total
                tier = project_tier.get(project, "unknown")
                if rate > 0.3 and tier not in ("untrusted", "regulated"):
                    report.add(LintFinding(
                        category="tier_drift",
                        severity="warn",
                        subject=project,
                        detail=f"block rate {rate:.0%} ({blocked}/{total}) but registered as tier={tier}",
                        suggestion=f"Consider downgrading '{project}' to 'untrusted' or 'regulated' tier.",
                    ))
        except Exception as e:
            logger.debug("tier drift check skipped: %s", e)

    async def _check_stale_rules(
        self, db, report: LintReport, window_days: int
    ) -> None:
        """Policy rules that fired >60 days ago - may be dead code."""
        try:
            async with db.execute("""
                SELECT
                    rule_name,
                    MAX(occurred_at) AS last_fired,
                    COUNT(*) AS total_fires
                FROM provenance_events
                WHERE
                    event_type = 'enforcement'
                    AND rule_name IS NOT NULL
                    AND rule_name != ''
                GROUP BY rule_name
                HAVING last_fired < datetime('now', '-60 days')
                ORDER BY last_fired ASC
                LIMIT 20
            """) as cur:
                rows = await cur.fetchall()

            for row in rows:
                report.add(LintFinding(
                    category="stale_rule",
                    severity="info",
                    subject=row["rule_name"],
                    detail=f"last fired {row['last_fired']} ({row['total_fires']} lifetime fires)",
                    suggestion="Verify this rule is still needed. If the threat it guards against is gone, remove or archive it.",
                ))
        except Exception as e:
            logger.debug("stale rule check skipped: %s", e)

    async def _check_contradictions(
        self, db, report: LintReport, window_days: int
    ) -> None:
        """Pattern names that triggered both blocking and audit-only actions - conflicting policy."""
        try:
            async with db.execute("""
                SELECT
                    pattern_name,
                    GROUP_CONCAT(DISTINCT action) AS actions,
                    COUNT(*) AS total
                FROM provenance_events
                WHERE
                    event_type = 'enforcement'
                    AND pattern_name IS NOT NULL
                    AND pattern_name != ''
                    AND occurred_at > datetime('now', :window)
                GROUP BY pattern_name
                HAVING
                    actions LIKE '%deny%' OR actions LIKE '%block%' OR actions LIKE '%exclude%'
            """, {":window": f"-{window_days} days"}) as cur:
                rows = await cur.fetchall()

            for row in rows:
                actions_str = row["actions"] or ""
                action_list = [a.strip() for a in actions_str.split(",")]
                blocking = [a for a in action_list if a in ("deny", "block", "exclude")]
                permissive = [a for a in action_list if a in ("audit-only", "warn")]
                if not (blocking and permissive):
                    continue
                report.add(LintFinding(
                    category="contradiction",
                    severity="warn",
                    subject=row["pattern_name"],
                    detail=f"same pattern triggered {blocking} and {permissive} within {window_days} days ({row['total']} events)",
                    suggestion="Check policy layering - a lower-priority rule may be overriding a fleet deny with audit-only.",
                ))
        except Exception as e:
            logger.debug("contradiction check skipped: %s", e)

    # ── Persistence ───────────────────────────────────────────────────────────

    async def _persist(self, report: LintReport) -> None:
        try:
            db = await get_db()
            await db.execute("DELETE FROM lint_findings")
            await db.executemany(
                """
                INSERT INTO lint_findings
                    (ran_at, window_days, category, severity, subject, detail, suggestion)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (report.ran_at, report.window_days,
                     f.category, f.severity, f.subject, f.detail, f.suggestion)
                    for f in report.findings
                ],
            )
            await db.commit()
        except Exception as e:
            logger.warning("lint findings persist failed (non-fatal): %s", e)

    async def get_latest(self) -> dict[str, Any] | None:
        """Return the most recent lint run from the DB."""
        try:
            db = await get_db()
            async with db.execute(
                "SELECT MAX(ran_at) AS ran_at, MAX(window_days) AS window_days FROM lint_findings"
            ) as cur:
                meta = await cur.fetchone()
            if not meta or not meta["ran_at"]:
                return None

            ran_at = meta["ran_at"]
            window_days = meta["window_days"]

            async with db.execute(
                "SELECT category, severity, subject, detail, suggestion FROM lint_findings WHERE ran_at = ?",
                (ran_at,),
            ) as cur:
                rows = await cur.fetchall()

            findings = [
                LintFinding(
                    category=r["category"],
                    severity=r["severity"],
                    subject=r["subject"],
                    detail=r["detail"],
                    suggestion=r["suggestion"],
                )
                for r in rows
            ]
            summary: dict[str, int] = {}
            for f in findings:
                summary[f.severity] = summary.get(f.severity, 0) + 1
                summary[f.category] = summary.get(f.category, 0) + 1

            return LintReport(ran_at=ran_at, window_days=window_days, findings=findings, summary=summary).as_dict()
        except Exception as e:
            logger.warning("lint get_latest failed: %s", e)
            return None
