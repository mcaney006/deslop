use crate::score::{Gate, Severity};
use crate::{hit, Finding, Src};

pub fn scan(src: &Src<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let joined = src.raw;
    let lower = joined.to_ascii_lowercase();

    for (n, line) in &src.lines {
        let t = line.trim();
        let l = t.to_ascii_lowercase();

        if l.contains("params.permit!") {
            out.push(hit(
                "rails.permit_bang",
                Gate::Think,
                Severity::Fatal,
                *n,
                col(line, "permit!"),
                t,
                "params.permit! is an untyped hole through strong parameters. Mass assignment with extra keys is how user_id, admin, balance get written.",
                "Permit an explicit allowlist: params.require(:load).permit(:pro_number, :weight_lbs).",
                "Let K = attacker-controlled keys. permit! ⇒ |writable| = |K|. allowlist A ⇒ |writable ∩ K| ≤ |A|.",
            ));
        }
        if l.contains("skip_before_action") && (l.contains("auth") || l.contains("authenticate") || l.contains("verify")) {
            out.push(hit(
                "rails.skip_auth",
                Gate::Goal,
                Severity::Fatal,
                *n,
                1,
                t,
                "Auth filter skipped. An unauthenticated index is not a feature unless you can name the public contract and the audit trail.",
                "Keep the filter. If a single action is public, skip only that action and add a request spec that 401s the rest.",
                "Auth is a pre-condition P. skip_before_action ¬P for the action. Goal-driven: write the 401 example first.",
            ));
        }
        if l.contains("html_safe") || l.contains("raw(") || l.contains(".html_safe") {
            out.push(hit(
                "rails.html_safe",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "html_safe/raw marks attacker bytes as trusted HTML. XSS is not a styling issue.",
                "Use sanitize or a template that auto-escapes. If you must emit HTML, allowlist tags and write a request spec with a payload.",
                "Escape is the identity e(s) such that browser(e(s)) has no extra nodes. html_safe is e⁻¹ of a lie.",
            ));
        }
        if l.contains("eval(") || l.contains("instance_eval") || l.contains("class_eval") || l.contains("module_eval") {
            out.push(hit(
                "rails.eval",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "eval on a request path is remote code execution wearing a costume.",
                "Delete it. Use a case statement, a registry hash, or constantize against an allowlist.",
                "eval : String → ⊥. There is no type for 'whatever the user typed'.",
            ));
        }
        if l.contains("send(params") || l.contains("public_send(params") || l.contains("constantize") && l.contains("params") {
            out.push(hit(
                "rails.send_params",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "Dispatching a method/class from params is an open call gate. constantize without allowlist is RCE-adjacent.",
                "Map params[:type] through a frozen hash of permitted constants.",
                "Let M be the method table. send(params) = M[attacker]. Allowlist L ⊂ M.",
            ));
        }
        if l.contains("redirect_to params") || l.contains("redirect_to(params") {
            out.push(hit(
                "rails.open_redirect",
                Gate::Think,
                Severity::High,
                *n,
                1,
                t,
                "redirect_to params[:x] is an open redirect. Phish the session through your own 302.",
                "Redirect to a named route or allowlist of paths. Never a raw user URL.",
                "Location header is an output channel. User input must not choose the host.",
            ));
        }
        if (l.contains("where(\"") || l.contains("where('") || l.contains("find_by_sql") || l.contains("execute("))
            && (t.contains("#{") || l.contains("+ params") || l.contains("+params"))
        {
            out.push(hit(
                "rails.sql_interp",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "String-interpolated SQL. This is injection, not 'dynamic where'.",
                "Use where(col: value), Arel, or bind placeholders: where('mc = ?', params[:mc]).",
                "SQL grammar composed with attacker strings is a parser injection. Bindings keep data out of the grammar.",
            ));
        }
        if l.contains("update_all") || l.contains("delete_all") || l.contains("destroy_all") {
            if !l.contains("where") && !src.line(n.saturating_sub(1)).to_ascii_lowercase().contains("where") {
                out.push(hit(
                    "rails.unscoped_write",
                    Gate::Goal,
                    Severity::High,
                    *n,
                    1,
                    t,
                    "Unscoped bulk write. Relation#update_all on a wide scope is a production incident.",
                    "Chain an explicit where with a bounded id set. Wrap in a transaction. Spec the row count.",
                    "UPDATE without a selective predicate has selectivity 1. Cost = |table|.",
                ));
            }
        }
        if l.contains("default_scope") {
            out.push(hit(
                "rails.default_scope",
                Gate::Simple,
                Severity::High,
                *n,
                1,
                t,
                "default_scope is a silent WHERE that leaks into joins, counts, and unsuspecting associations.",
                "Use an explicit named scope. Query objects take a relation and return a relation.",
                "Hidden predicates violate referential transparency. r.to_sql must equal what the caller thinks it is.",
            ));
        }
        if l.contains("render json:") && (l.contains(".all") || l.contains(".all[")) {
            out.push(hit(
                "rails.render_all",
                Gate::Simple,
                Severity::High,
                *n,
                1,
                t,
                "Serializing Model.all dumps the table, including columns you forgot existed.",
                "Paginate. Use a Blueprinter/Alba/Jbuilder with an allowlisted field set.",
                "Response size ~ |rows| × |columns|. That is not an API, that is a backup.",
            ));
        }
        if l.contains("user.find(params") || l.contains("user.find_by(id: params") {
            out.push(hit(
                "rails.direct_find",
                Gate::Think,
                Severity::High,
                *n,
                1,
                t,
                "Direct find from params without an authorization predicate. IDOR lives here.",
                "Scope by current_user / org: current_user.loads.find(params[:id]). Pundit/policy on top.",
                "Authorization is a predicate A(user, resource). find(id) is ∃row, not A.",
            ));
        }
        if l.contains("rescue_from") && l.contains("exception") || t.contains("rescue Exception") || t.contains("rescue StandardError") && l.contains("end") {
            out.push(hit(
                "rails.swallow",
                Gate::Goal,
                Severity::Med,
                *n,
                1,
                t,
                "Broad rescue. Errors are evidence. Swallowing them is how you ship a 200 that lied.",
                "Rescue the specific class. Re-raise unknown. Log with request id.",
                "A catch-all maps every failure to silence. That destroys the test oracle.",
            ));
        }
        if l.contains("after_save") || l.contains("after_commit") || l.contains("after_create") {
            if l.contains("http") || l.contains("net::") || l.contains("faraday") || l.contains("httparty") {
                out.push(hit(
                    "rails.callback_io",
                    Gate::Simple,
                    Severity::High,
                    *n,
                    1,
                    t,
                    "HTTP inside an ActiveRecord callback. Transactions plus network is how you deadlock and double-charge.",
                    "Enqueue a job after_commit. The callback stays a state transition, not an RPC.",
                    "Callbacks must be O(memory). I/O belongs on an at-least-once worker with idempotency keys.",
                ));
            }
        }
        if l.contains("# TODO") || l.contains("# later") || l.contains("just in case") || l.contains("future proof") || l.contains("flexible") {
            out.push(hit(
                "rails.speculative",
                Gate::Simple,
                Severity::Low,
                *n,
                1,
                t,
                "Speculative comment or 'flexibility' flag. Karpathy gate 2: nothing that was not asked.",
                "Delete the branch. If the requirement exists, it has a test, not a comment.",
                "Speculative code has expected value ≈ 0 and carry cost > 0.",
            ));
        }
        if l.contains(".save(") && !l.contains("save!") && !l.contains("save ?") {
            // weak — skip
        }
        if l.contains(".save") && !l.contains("save!") && !l.contains("if ") && (l.contains(".save") && !l.contains("save!")) && (l.ends_with(".save") || l.contains(".save(") && !l.contains("save!")) {
            out.push(hit(
                "rails.save_silent",
                Gate::Goal,
                Severity::Med,
                *n,
                1,
                t,
                "save (no bang) returns false on validation failure. Ignoring it is a silent no-op that looks like success.",
                "Use save! / update! or branch on the boolean and render errors.",
                "Goal: persistence occurred. Oracle: bang or explicit false-path test.",
            ));
        }
    }

    n_plus_one(src, &mut out);
    if lower.contains("current_user") && lower.contains("params[:user") {
        if let Some((n, line)) = src.lines.iter().find(|(_, l)| {
            let x = l.to_ascii_lowercase();
            x.contains("current_user") && x.contains("params")
        }) {
            out.push(hit(
                "rails.user_spoof",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                line,
                "current_user derived from params. The client does not get to choose who they are.",
                "current_user comes from the session/Warden. Period.",
                "Identity is a server-side fact. Client input is a claim, not a credential.",
            ));
        }
    }
    out
}

fn n_plus_one(src: &Src<'_>, out: &mut Vec<Finding>) {
    let mut in_each = false;
    let mut each_line = 0;
    let mut assoc_hits = 0;
    let has_eager = src.raw.to_ascii_lowercase().contains("includes(")
        || src.raw.to_ascii_lowercase().contains("preload(")
        || src.raw.to_ascii_lowercase().contains("eager_load(");
    for (n, line) in &src.lines {
        let l = line.to_ascii_lowercase();
        if l.contains(".each") || l.contains(".map") || l.contains(".find_each") {
            in_each = true;
            each_line = *n;
            assoc_hits = 0;
        }
        if in_each {
            // association-shaped calls inside the loop
            if line.contains('.')
                && !l.contains(".each")
                && !l.contains(".map")
                && !l.contains("puts")
                && (l.contains(".name")
                    || l.contains(".user")
                    || l.contains(".carrier")
                    || l.contains(".stops")
                    || l.contains(".account")
                    || l.contains(".profile")
                    || l.contains(".orders")
                    || l.contains(".loads")
                    || l.contains(".first")
                    || l.contains(".last"))
            {
                assoc_hits += 1;
            }
            if l.trim() == "end" && assoc_hits >= 1 {
                if !has_eager {
                    out.push(hit(
                        "rails.n_plus_one",
                        Gate::Goal,
                        Severity::High,
                        each_line,
                        1,
                        src.line(each_line),
                        "Association access inside a loop with no includes/preload. Classic N+1: 1 + N queries, linear in page size, quadratic under nested assoc.",
                        "Load.includes(:carrier, :stops).find_each. Assert query count in a test (assert_queries / prosopite).",
                        "Cost ≈ 1 + N·k queries. With includes: 1 + k. Goal-driven: write the query-count assertion first.",
                    ));
                }
                in_each = false;
            }
        }
    }
}

fn col(line: &str, needle: &str) -> usize {
    line.find(needle).map(|i| i + 1).unwrap_or(1)
}
