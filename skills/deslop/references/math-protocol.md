# Math protocol (deslop)

Every finding in the crate carries a `math` field. That is not decoration. It is the invariant the rule is preserving.

## Scoring

```
weight(fatal)=28  weight(high)=14  weight(med)=7  weight(low)=3
gate_i = clamp_0_100(100 - Σ weight of findings on that gate)
deslop = round(0.30 think + 0.25 simple + 0.20 surgical + 0.25 goal)
if any fatal: deslop = min(deslop, 45)
if lines = 0: deslop = 0
```

Fatal is a hard cap because a single `OR 1=1` or `permit!` makes a 91 on "style" a lie.

## Rails N+1

```
queries ≈ 1 + N · k
includes/preload ⇒ 1 + k
```

N is page size, k is associations touched in the loop. Goal-driven: `assert_queries` / Prosopite, not a vibe that "it's cached".

## SQL selectivity

```
FROM a, b           = a × b          cardinality |a|·|b|
P ∨ ⊤               = ⊤              selectivity 1
f(col) = k          non-sargable     btree on col unused
LIKE '%x'           no lower bound   seq scan
DELETE without WHERE                 |Δ| = |T|
OFFSET k            Θ(k) discarded   keyset is Θ(limit)
```

Three-valued logic: `x NOT IN (…, NULL)` ⇒ UNKNOWN ⇒ row dropped. That is a bug.

## XSS

```
v-html / html_safe : String → DOM
escape : String → String  s.t. parse(escape(s)) has no extra nodes
```

If the domain of the string includes a user, the morphism must be escape, not identity.

## Do not

- Print six significant figures from a one-significant-figure input.
- Use big-O as a latency promise.
- Multiply buzzwords by Greek letters.
