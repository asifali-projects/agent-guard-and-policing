"""Runtime Guard — the deterministic authorization path (PRD §24–25, §42).

Critical path: authenticate -> identify agent -> identify tool -> validate
parameters -> policy check -> risk -> DLP -> decision. It must stay lightweight
and must not depend on an LLM.
"""
