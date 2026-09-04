<!--
Thanks for the PR. Please skim the checklist before submitting.
Full guidance in CONTRIBUTING.md and docs/METHODOLOGY.md.
-->

## What this changes

<!-- 1-3 sentences on the change and why. Link to the issue if there is one. -->

## Type of change

- [ ] Bug fix
- [ ] New fixture proposal
- [ ] Grader / detector improvement
- [ ] Documentation
- [ ] Refactor / cleanup
- [ ] Other:

## Checklist

- [ ] All existing tests pass locally: `uv run pytest tests/preflight/`
- [ ] If you added a fixture, you also added **at least one pass example and
      one fail example** to `tests/preflight/test_grader_regression.py`
- [ ] If you changed the grader, the regression harness still passes and the
      change is documented
- [ ] If you cited a CVE / paper / disclosure, please include the link in the
      fixture `citation:` field or PR description
- [ ] If this changes public behavior, `CHANGELOG.md` has an entry
- [ ] `ruff format` + `ruff check` are clean

## Anything else

<!-- Screenshots, benchmark numbers, edge cases considered, etc. -->
