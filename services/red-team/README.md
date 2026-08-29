# services/red-team

Offensive security engine (Python). A **first-class product**, not an add-on
(PRD §18).

Pipeline (PRD §20):

```
Target Agent → Attack Planner → Attack Generator → Execution Sandbox
            → Observation → Evaluator → Risk Classification → Finding
```

Every test records: Attack ID, Category, Technique, Input, Expected Security
Behavior, Observed Behavior, Severity, Evidence, Recommendation.

Attack categories (PRD §19): Prompt, Tool, Data, Agent, MCP, Availability.

Assessment profiles (PRD §18): Quick, Standard, Deep, Enterprise, Custom.

Implemented in **Step 6**. Continuous / CI-triggered red-teaming (PRD §21) is
wired in the same step.
