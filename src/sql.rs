use crate::score::{Gate, Severity};
use crate::{hit, Finding, Src};

pub fn scan(src: &Src<'_>) -> Vec<Finding> {
    let mut out = Vec::new();

    for (n, line) in &src.lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with("--") {
            continue;
        }
        let u = t.to_ascii_uppercase();

        if u.contains("SELECT *") || u.contains("SELECT*") {
            out.push(hit(
                "sql.select_star",
                Gate::Simple,
                Severity::High,
                *n,
                1,
                t,
                "SELECT * couples the query to every future column, including PII someone adds next quarter. Also kills covering indexes.",
                "Name the columns the contract needs. If you need 'all', you need a versioned view.",
                "Projection π_C. SELECT * is π_{all columns at t}. Schema evolution silently changes the result arity.",
            ));
        }
        if comma_join(&u) {
            out.push(hit(
                "sql.comma_join",
                Gate::Think,
                Severity::High,
                *n,
                1,
                t,
                "Comma FROM list is an implicit CROSS JOIN until the WHERE accidentally saves you. 1992 syntax.",
                "INNER JOIN ... ON. Make the predicate visible.",
                "FROM a, b = a × b. Filter later is not a join. Cardinality |a|·|b| until a predicate exists.",
            ));
        }
        if u.contains("OR 1=1")
            || u.contains("OR 1 = 1")
            || u.contains("OR '1'='1'")
            || u.contains("OR TRUE")
        {
            out.push(hit(
                "sql.tautology",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "Tautology in WHERE. Either a leftover injection payload or a clown. Either way the predicate is gone.",
                "Delete it. The WHERE stands on real predicates.",
                "P ∨ ⊤ = ⊤. Selectivity = 1. You just full-scanned on purpose.",
            ));
        }
        if fn_on_col(&u) {
            out.push(hit(
                "sql.fn_on_column",
                Gate::Goal,
                Severity::High,
                *n,
                1,
                t,
                "Function on a filtered column (LOWER/TRIM/DATE wrapping the column) makes the predicate non-sargable. Index skipped.",
                "Store a canonical form (citext, generated column) and compare raw. WHERE mc_number = $1.",
                "A B-tree on col cannot satisfy f(col) = k unless f is monotonic and the planner proves it. It will not.",
            ));
        }
        if u.contains("LIKE '%") || u.contains("LIKE '%") {
            out.push(hit(
                "sql.leading_wildcard",
                Gate::Goal,
                Severity::Med,
                *n,
                1,
                t,
                "LIKE '%x' cannot use a btree. You will seq-scan. At 10M rows this is a production incident wearing a search box.",
                "pg_trgm GIN, prefix LIKE 'x%', or an external search index. Measure EXPLAIN ANALYZE.",
                "B-tree range scan requires a lower bound. Leading % removes it. Cost → O(|table|).",
            ));
        }
        if u.contains("NOT IN (") {
            out.push(hit(
                "sql.not_in",
                Gate::Think,
                Severity::High,
                *n,
                1,
                t,
                "NOT IN with a NULL in the list makes the whole predicate UNKNOWN. Rows vanish mysteriously. Three-valued logic is not optional.",
                "NOT EXISTS (SELECT 1 FROM ... WHERE ...). Or `col NOT IN (...)` over a non-null subquery.",
                "x NOT IN (a, NULL) ⇒ x≠a AND x≠NULL ⇒ x≠a AND UNKNOWN ⇒ UNKNOWN. Filtered out. That is a bug, not a feature.",
            ));
        }
        if u.starts_with("DELETE FROM") || u.starts_with("DELETE ") {
            if !u.contains("WHERE") && !lookahead_where(src, *n) {
                out.push(hit(
                    "sql.unbounded_delete",
                    Gate::Goal,
                    Severity::Fatal,
                    *n,
                    1,
                    t,
                    "DELETE without WHERE. The table is the predicate. Congratulations, you truncated with extra steps.",
                    "DELETE FROM t WHERE id = $1. Require a bound key. In a transaction. Returning id.",
                    "DELETE cardinality without predicate = |T|. Goal: |Δ| = 1, asserted.",
                ));
            }
        }
        if u.starts_with("UPDATE ") {
            if !u.contains("WHERE") && !lookahead_where(src, *n) {
                out.push(hit(
                    "sql.unbounded_update",
                    Gate::Goal,
                    Severity::Fatal,
                    *n,
                    1,
                    t,
                    "UPDATE without WHERE. Every row just became the new status. Hope you liked backups.",
                    "UPDATE t SET ... WHERE id = $1. Check ROW_COUNT.",
                    "Same as unbounded delete. Selectivity 1 is not an update, it is a rewrite of the relation.",
                ));
            }
        }
        if t.contains("${") || (t.contains("'") && t.contains("+") && (u.contains("WHERE") || u.contains("VALUES"))) {
            if t.contains("+") && !t.contains("++") {
                out.push(hit(
                    "sql.string_concat",
                    Gate::Think,
                    Severity::Fatal,
                    *n,
                    1,
                    t,
                    "SQL built by string concatenation. Injection is a grammar problem, not a sanitization problem.",
                    "Parameterized query. $1, $2. Never interpolate.",
                    "Data must not enter the parser. Bindings keep the AST shape constant.",
                ));
            }
        }
        if u.contains("OFFSET") {
            let off = extract_int_after(&u, "OFFSET");
            if off.map(|v| v > 1000).unwrap_or(false) {
                out.push(hit(
                    "sql.deep_offset",
                    Gate::Goal,
                    Severity::Med,
                    *n,
                    1,
                    t,
                    "Deep OFFSET walks discarded rows. Page 5000 of a feed is O(offset).",
                    "Keyset pagination: WHERE (created_at, id) < ($1, $2) ORDER BY created_at DESC, id DESC LIMIT n.",
                    "OFFSET k costs Θ(k) even if LIMIT is small. Keyset is Θ(limit) with a matching index.",
                ));
            }
        }
        if u.contains("ORDER BY RANDOM()") || u.contains("ORDER BY RAND()") {
            out.push(hit(
                "sql.order_random",
                Gate::Simple,
                Severity::Med,
                *n,
                1,
                t,
                "ORDER BY random() sorts the table. Cute in dev. A weapon in prod.",
                "TABLESAMPLE or a precomputed shuffle key.",
                "Random sort is O(n log n) with a seq scan. You asked for a coin flip, you paid for a sort.",
            ));
        }
        if u.contains("COUNT(") && u.contains("SELECT") && !src.raw.to_ascii_uppercase().contains("LIMIT") {
            // too noisy
        }
        if u.contains("LOCK TABLE") || u.contains("FOR UPDATE") && !u.contains("SKIP LOCKED") && !u.contains("NOWAIT") {
            if u.contains("FOR UPDATE") {
                out.push(hit(
                    "sql.for_update",
                    Gate::Think,
                    Severity::Low,
                    *n,
                    1,
                    t,
                    "FOR UPDATE without SKIP LOCKED/NOWAIT can queue behind a stuck txn until statement_timeout.",
                    "Know the isolation level. For worker claims: FOR UPDATE SKIP LOCKED.",
                    "Row locks are a queue. Unbounded wait is a deadlock lottery.",
                ));
            }
        }
    }

    // statement-level: DELETE/UPDATE with no WHERE anywhere in file
    unbounded_dml(src, &mut out);
    out
}

fn comma_join(u: &str) -> bool {
    if let Some(rest) = u.split_once("FROM ") {
        let head = rest.1.split("WHERE").next().unwrap_or(rest.1);
        let head = head.split("JOIN").next().unwrap_or(head);
        head.contains(',') && !head.contains('(')
    } else {
        false
    }
}

fn fn_on_col(u: &str) -> bool {
    const FNS: [&str; 8] = [
        "LOWER(", "UPPER(", "TRIM(", "DATE(", "CAST(", "SUBSTRING(", "TO_CHAR(", "DATE_TRUNC(",
    ];
    if !u.contains("WHERE") && !u.contains("AND ") && !u.contains("ON ") {
        return false;
    }
    FNS.iter().any(|f| {
        if let Some(i) = u.find(f) {
            // function wrapping a column, not a literal — crude: next char is not quote
            let after = u[i + f.len()..].trim_start();
            after.starts_with(char::is_alphabetic)
        } else {
            false
        }
    })
}

fn lookahead_where(src: &Src<'_>, n: usize) -> bool {
    src.lines
        .iter()
        .filter(|(i, _)| *i > n && *i <= n + 6)
        .any(|(_, l)| l.to_ascii_uppercase().contains("WHERE"))
}

fn unbounded_dml(src: &Src<'_>, out: &mut Vec<Finding>) {
    let mut stmt = String::new();
    let mut start = 0usize;
    for (n, line) in &src.lines {
        if start == 0 {
            start = *n;
        }
        stmt.push_str(line);
        stmt.push('\n');
        if line.contains(';') {
            let u = stmt.to_ascii_uppercase();
            let is_del = u.trim_start().starts_with("DELETE");
            let is_upd = u.trim_start().starts_with("UPDATE");
            if (is_del || is_upd) && !u.contains("WHERE") {
                let id = if is_del {
                    "sql.unbounded_delete"
                } else {
                    "sql.unbounded_update"
                };
                if !out.iter().any(|f| f.id == id && f.line == start) {
                    out.push(hit(
                        id,
                        Gate::Goal,
                        Severity::Fatal,
                        start,
                        1,
                        src.line(start),
                        "DML statement has no WHERE anywhere in the statement. Full relation rewrite.",
                        "Add a keyed WHERE. Assert ROW_COUNT.",
                        "Relational update without restriction is assignment to the whole table.",
                    ));
                }
            }
            stmt.clear();
            start = 0;
        }
    }
}

fn extract_int_after(u: &str, kw: &str) -> Option<i64> {
    let i = u.find(kw)?;
    let rest = u[i + kw.len()..].trim();
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}
