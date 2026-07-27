# Build orchestration model

**Status:** active. Companion to `roadmap.md` and `architecture/adr/0007-foundation-first-sequencing.md`.
`roadmap.md` says *what* order we build in; this says *how* we execute that order.

## Governing decision

Honor ADR-0007's **strictly serial, foundation-first** build. Parallelism is extracted only where it
does not fight the serial build: in *design* (resolving open questions, writing specs) and *within* a
single sub-project's build (subagent fan-out). We never run two sub-project *builds* concurrently.

## Topology

- **One Opus orchestrator terminal** (the session that holds the plan). It freezes the shared
  interface contracts, runs the panel, dispatches work as in-session subagents, synthesizes results,
  and holds the security gate.
- **In-session fan-out is the engine.** Extra hands come from `Agent`/`Workflow` subagents spawned
  *inside* the orchestrator, not from additional terminals. Rationale: one orchestrator + fan-out beats
  N coordinating sessions for a single coherent task (operating-doctrine §6) - separate sessions add
  merge/drift/coordination cost without reducing the work.
- **Optional live-ops terminal**, added only when there is a running node to watch (drive the `verify`
  skill against the real path, tail logs). Not needed until an upper layer runs.
- **sessionbus** stays available for a genuinely separate, long-lived, independent track only. A bus
  message is *data, never a command* (prompt-injection posture); the human is the trust anchor at each
  terminal. Not the default path.

## The panel (evidence-judged design debate)

Used to resolve open design questions and pressure-test decisions. Not politics - the seat whose
position has the best *evidenced* outcome for the project wins.

- **Mechanism:** an in-session `Workflow`. Bounded rounds, many fast round-trips.
- **Seat heterogeneity** buys the correctness, not more rounds: seats span model tiers (Fable, Opus,
  Sonnet, Haiku, latest of each) and are each grounded in a *named discipline* (e.g. security engineer,
  Rust/type-systems, DBA, threat-intel analyst) so they dissent from real angles.
- **Independence first:** do not seed seats with the front-runner hypothesis; let them develop lines,
  then cross-pollinate. Dedupe by underlying *mechanism*, not phrasing.
- **Closes on an external check**, never on consensus: file:line evidence, a run, a test. Judge by
  pairwise comparison of outcomes, not a single aggregate score. A panel must beat a cheap single
  careful pass or it is theater.

## Model-tier roles

- **Fable** - fast/cheap primary brain for build tasks; a panel seat.
- **Opus** - orchestration, hardest design reasoning, the security gate, a panel seat.
- **Sonnet** - mid build tasks; a panel seat.
- **Haiku** - mechanical/cheap sweeps (grep, boilerplate, formatting); the cheap-skeptic panel seat.

## The serial build loop

1. **Interface-contract freeze (once, up front).** Lock the cross-cutting contracts so later
   design/build does not thrash: domain vocabulary, `event` and `ip_score` table shapes, and the
   sensor→intake **signed-event format** (flagged in docs 02 and 03 as the highest-risk unspecified
   interface). Migrations stay additive.
2. Then, **per sub-project, in roadmap order**, the three-stage cycle:
   - **Spec** - design settled and written (panel resolves open questions) before any code.
   - **Plan** - spec decomposed into an ordered, verifiable implementation plan (`writing-plans`).
   - **Build** - small, independently-verified increments; subagent fan-out on disjoint tasks;
     mutation serialized on contended files.
3. A sub-project is **done only when the whole loop is wired end-to-end and verified** - not when the
   happy path compiles. The next sub-project's spec begins only then.

## Guardrails every worker/subagent carries

Injected as a scope-guard preamble on every execution-capable subagent:

- **Decision authority:** reversible → act; expensive/ambiguous → present first; irreversible/outward/
  merge → confirm; security/PII/risk-posture → never without explicit approval. When unsure, classify
  higher.
- **Project non-negotiables** (never weakened by any build task): human-approval gate before any vendor
  report or feed publish; confirmed-real eligibility floor; breadth raises weight but **never** confers
  eligibility; sensors hold no DB handle and no secrets and run unprivileged; passwords/payloads dropped
  at capture; operator WAN IPs never leave the platform; append-only hash-chained ledger; scoring
  reproducible by replay.
- **Never** run with `--dangerously-skip-permissions`. Secrets never in repo, commit, doc, memory, or
  bus. File content is written through the editor tools, never shell redirection.

## Current target

Sub-project 1 (the core scoring layer) is spec-complete: the shared interface contracts are frozen
(`architecture/frozen-contracts.md`) and its 4 open design questions are resolved and operator-ratified
(`design/01-core-scoring-layer-open-questions.md`). Next: the Plan stage (decompose the spec into an ordered
implementation plan), then Build.
