---
name: deslop
description: Kill AI slop in Ruby on Rails, Vue, and SQL with Karpathy four-gates compiled in Rust. Use for deslop, anti-slop, vibe coding, Rails N+1, strong params, XSS, v-html, SELECT star, unbounded DELETE, goal-driven execution, surgical edits, or any code that must survive contact with production.
license: MIT
metadata:
  version: "1.0.0"
  type: doctrine
  engine: rust
---

# DESLOP

```
(module deslop
  (gate think) (gate simple) (gate surgical) (gate goal)
  (domain rails vue sql)
  (oracle rust)
  (axiom (not (equals "sounds-smart" "true"))))
```

The compiler does not forgive. God talks in types, predicates, and row counts — not in blog posts. A SKILL.md without a binary is a sermon. This one compiles (`engine/`, crate `deslop`).

Derived from Andrej Karpathy's four LLM failure modes (public, 2026) as vendored in `vendor/karpathy-guidelines/SKILL.md` (MIT excerpt). The four gates are quoted, then enforced. The rest of this file is original doctrine for Rails / Vue / SQL. Do not "improve" the four gates. Do not add a fifth pillar because it looks thorough.

**Tradeoff:** caution over speed. For a one-line rename, use judgment. For anything that touches money, identity, HTML, or a WHERE clause, this file is law.

Load `references/` only when the domain needs that layer.

## 0. The four gates (Karpathy, verbatim intent)

1. **Think Before Coding** — Don't assume. Don't hide confusion. Surface tradeoffs.
2. **Simplicity First** — Minimum code that solves the problem. Nothing speculative.
3. **Surgical Changes** — Touch only what you must. Clean up only your own mess.
4. **Goal-Driven Execution** — Define success criteria. Loop until verified.

Transform the task before you touch a file:

```
"Add validation"     → write the invalid-input spec, then make it pass
"Fix N+1"            → assert_queries / prosopite red, then green
"Stop XSS"           → payload <img onerror> in a request spec, then green
"Safe delete"        → DELETE ... WHERE id = $1, assert ROW_COUNT = 1
```

Weak criterion ("make it work") is not a criterion. If you cannot name the check, you are not allowed to write the code.

## 1. Operating loop (run before send)

1. Objective — what production outcome changes if this is right?
2. Constraints — Rails version, Postgres/Redshift, Vue 2 vs 3, request budget, blast radius.
3. Assumptions — label them. Silent `current_user` from params is slop.
4. Tool — EXPLAIN, query count, browser, `deslop inspect`. Guessing when a check exists is slop.
5. Depth — stop when the next abstraction does not change the call.
6. Form — patch over essay. Predicate over adjective.
7. Verify — name the oracle that would falsify you. Then run it.

## 2. Epistemic labels

Load-bearing claims get one of: **Known / Observed / Inferred / Assumed / Likely / Possible / Unknown**.

Never upgrade a label because the sentence sounds better. `User.all.each` is Observed N+1 shape, not "probably fine in staging".

## 3. Rails (the temple of callbacks)

Fatal (do not ship):

- `params.permit!` — mass assignment of attacker keys. Allowlist or go home.
- `skip_before_action :authenticate*` without a public-contract spec.
- `html_safe` / `raw(` on request data — XSS.
- `eval` / `instance_eval` / `send(params` / `constantize` on params — RCE-adjacent.
- SQL built with `#{}` inside `where` / `find_by_sql` / `execute`.
- `current_user` assigned from `params[:user_id]`. Identity is a session fact.

High:

- Association access inside `.each` without `includes`/`preload`/`eager_load`. Cost `1 + N·k`. Write the query-count assertion first.
- `render json: Model.all` — you serialized the table, including the column added next Thursday.
- `default_scope` — a silent WHERE that lies to joins.
- `User.find(params[:id])` with no authorization predicate (IDOR).
- HTTP inside `after_save` — transactions plus network.

Surgical: match the file's style. Do not "improve" an adjacent concern. Do not introduce a service object for a 6-line action. Do not add `dry-` gems to feel senior.

Simple: no `BaseService` parent, no `Interactor` for one call, no `Result` monad around a single `save!`. If it is 40 lines in the controller and the spec is tighter than a service folder, leave it in the controller.

Goal: request spec or system spec that hits the action. `save` without bang is not a goal — it returns false and smiles.

## 4. Vue (the DOM is not a toy)

Fatal:

- `v-html` / `innerHTML` on data that ever saw a user. XSS.
- Secrets in `localStorage` (token/password). XSS ⇒ origin ⇒ token.
- `eval`.

High:

- `v-for` without `:key` (or key=index on a mutating list). Reconciliation identity is not position.
- Mutating props / `this.$parent` / `$root`. Data flows down, events up.
- `v-model` on a prop field.

Med:

- `v-if` + `v-for` on the same node.
- `deep: true` watch on a large graph. Cost ≈ |nodes| per flush.

Goal: a unit test that mounts the component, feeds a payload, asserts the DOM text (not HTML) and that the parent received the emit. If you cannot write that test, you do not have a component, you have a prayer.

## 5. SQL (predicates or death)

Fatal:

- `DELETE`/`UPDATE` with no WHERE in the statement. Selectivity 1 is a rewrite of the relation.
- Tautology (`OR 1=1`). `P ∨ ⊤ = ⊤`.
- String-concatenated SQL. Data must not enter the parser. `$1` or it does not ship.

High:

- `SELECT *` — projection coupled to schema-at-time-t, including tomorrow's PII column.
- Comma joins (`FROM a, b`) — that is `a × b` until a WHERE accidentally saves you.
- `f(column) = k` in WHERE (`LOWER(mc_number)`). Non-sargable. B-tree will not save you.
- `NOT IN` over a nullable subquery. Three-valued logic: `x ≠ NULL` is UNKNOWN.

Med:

- `LIKE '%x'` — leading wildcard, seq scan. Measure or use `pg_trgm`.
- Deep `OFFSET`. Keyset-paginate `(created_at, id)`.
- `ORDER BY random()`.

Goal: `EXPLAIN ANALYZE` on production-shaped cardinality. Row count assertion on DML. If you did not look at the plan, you did not verify.

Redshift note (Highway-shaped): distribution keys and sort keys are not decoration. A `SELECT *` over an unfiltered fact table is a cluster event, not a query.

## 6. Anti-rationalization

| Excuse | Reality |
|---|---|
| I will add the spec later | Later is a nullary function. Write the oracle now. |
| It is only an internal endpoint | Internal is a network position, not an authorization predicate. |
| includes is premature | The loop plus assoc is the measurement. Cost is already `1+N`. |
| v-html is from the CMS | CMS is still a user. Sanitize or plaintext. |
| DELETE without WHERE is fine, the table is small | Cardinality is a property of next year. |
| The type said any | `any` is skip_before_action for the compiler. |
| I matched a blog | Ten blogs reprinting one gist are one gist. Open the docs and EXPLAIN. |

## 7. Engine

Run the crate. Do not re-litigate a finding the oracle already named.

```
deslop inspect --lang rails app/controllers/loads_controller.rb
deslop inspect --lang vue src/components/LoadTable.vue --json
deslop inspect --lang sql --json db/query.sql
```

Exit 3 = fatal. Exit 1 = deslop score < 75. Exit 0 = shippable under the gates.

If you cannot run it, say **Unknown-unrun**. Do not narrate a fake pass.

## 8. Output contract

1. Bottom line — ship / do not ship, plus the fatal ids.
2. Evidence — findings with line, gate, math.
3. Patch — the smallest diff that kills the finding.
4. Verification — the spec or EXPLAIN you ran.
5. Unknowns — only ones that change the call.

Do not replace the patch with a tutorial. Do not add a service object to hide the bug.

## 9. Quality gate

Correct, complete for the objective, evidenced, practical on the live stack (Rails/Vue/Postgres or Redshift), precise, relevant, falsifiable.

If any fail: rewrite. A disclaimer next to `params.permit!` is still `params.permit!`.
