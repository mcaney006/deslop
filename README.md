# DESLOP

The compiler does not forgive.

Karpathy's four LLM coding gates, compiled into a **Rust** analyzer for **Ruby on Rails**, **Vue**, and **SQL**. A `SKILL.md` without a binary is a sermon. This one exits `3` when you try to ship `params.permit!`.

```
(module deslop
  (gate think) (gate simple) (gate surgical) (gate goal)
  (domain rails vue sql)
  (oracle rust))
```

## Why this exists

Public "anti-slop" skills are either coding manners (Karpathy's four rules) or SDLC choreography. None of them grade **this statement** on the stack that actually pages people:

- Rails N+1, `permit!`, interpolated SQL, IDOR `find(params[:id])`, `html_safe`
- Vue `v-html`, `v-for` without key, prop mutation, `$parent`
- SQL `SELECT *`, comma joins, `OR 1=1`, unbounded `DELETE`/`UPDATE`, `LOWER(column)`

This crate does. Deterministic. No Python. No network. No model.

## The four gates (Karpathy)

Vendored excerpt with attribution: [`vendor/karpathy-guidelines/SKILL.md`](vendor/karpathy-guidelines/SKILL.md), derived from [Karpathy's 2026 observations](https://x.com/karpathy/status/2015883857489522876) and the MIT-licensed community packaging in `forrestchang/andrej-karpathy-skills`.

1. **Think Before Coding** — Don't assume. Don't hide confusion. Surface tradeoffs.
2. **Simplicity First** — Minimum code that solves the problem. Nothing speculative.
3. **Surgical Changes** — Touch only what you must. Clean up only your own mess.
4. **Goal-Driven Execution** — Define success criteria. Loop until verified.

The rest of [`skills/deslop/SKILL.md`](skills/deslop/SKILL.md) is original doctrine for Rails / Vue / SQL. We do not copy the rest of that plugin marketplace. We enforce the gates.

## Install the agent skill

Copy `skills/deslop/` into your agent's skills directory (Claude Code: `~/.claude/skills/deslop`, Codex/Grok: `.grok/skills/deslop`).

## CLI

```bash
cargo install --path .
deslop inspect --lang rails app/controllers/loads_controller.rb
deslop inspect --lang vue src/components/LoadTable.vue --json
deslop inspect --lang sql query.sql
```

Exit codes: `0` deslop ≥ 75 and no fatal, `1` slop, `3` fatal, `2` usage.

## Library

```rust
let report = deslop::analyze(deslop::Lang::Sql, sql);
assert!(report.score.fatal == 0);
```

Score:

```
gate_i  = clamp(100 - Σ weight(severity))
deslop  = 0.30 think + 0.25 simple + 0.20 surgical + 0.25 goal
fatal   ⇒ deslop := min(deslop, 45)
```

Weights: fatal 28, high 14, med 7, low 3.

## WASM

```bash
cargo build --lib --release --target wasm32-unknown-unknown
```

Exports (empty import object — instantiates in the browser):

| export | meaning |
|---|---|
| `deslop_alloc(n) -> ptr` | bump input |
| `deslop_analyze(ptr, len, lang) -> out_len` | lang: 0 rails, 1 vue, 2 sql |
| `deslop_out_ptr() -> ptr` | JSON report |
| `deslop_free(ptr, n)` | release input |

## Tests

```bash
cargo test --lib
```

## License

MIT. Karpathy excerpt remains MIT; see `NOTICE`.
