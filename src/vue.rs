use crate::score::{Gate, Severity};
use crate::{hit, Finding, Src};

pub fn scan(src: &Src<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line) in &src.lines {
        let t = line.trim();
        let l = t.to_ascii_lowercase();

        if l.contains("v-html") {
            out.push(hit(
                "vue.v_html",
                Gate::Think,
                Severity::Fatal,
                *n,
                col(line, "v-html"),
                t,
                "v-html injects raw HTML. If the string ever touched a user, you just bought XSS.",
                "Render text. If you must render HTML, sanitize with DOMPurify and a tag allowlist, then add a unit test with <img onerror>.",
                "v-html : String → DOM. That morphism is unsafe unless the domain is already a sanitized AST.",
            ));
        }
        if l.contains("innerhtml") {
            out.push(hit(
                "vue.innerhtml",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "innerHTML is v-html with extra steps. Same XSS, worse taste.",
                "textContent or a Vue text binding.",
                "The HTML parser is not your friend. Do not feed it attacker strings.",
            ));
        }
        if l.contains("v-for") && !l.contains(":key") && !l.contains("v-bind:key") && !l.contains("key=") {
            out.push(hit(
                "vue.vfor_no_key",
                Gate::Goal,
                Severity::High,
                *n,
                col(line, "v-for"),
                t,
                "v-for without key. Vue reuses DOM nodes by position. You will patch the wrong row after a splice.",
                "v-for=\"item in items\" :key=\"item.id\". Never the index unless the list is static and append-only.",
                "Reconciliation is a matching problem. Index keys make identity = position, which is false after permutation.",
            ));
        }
        if l.contains("v-for") && l.contains("v-if") {
            out.push(hit(
                "vue.vfor_vif",
                Gate::Simple,
                Severity::Med,
                *n,
                1,
                t,
                "v-if and v-for on the same node. Priority is version-dependent. Readers will guess wrong.",
                "Wrap: template v-for + inner node v-if, or computed filtered list.",
                "Two directives, one node, undefined composition. Split the morphisms.",
            ));
        }
        if l.contains("this.$parent") || l.contains("$parent.") {
            out.push(hit(
                "vue.parent",
                Gate::Surgical,
                Severity::High,
                *n,
                1,
                t,
                "$parent reaches out of the component. Surgical changes become archaeology.",
                "Emit an event, provide/inject with a named contract, or lift state.",
                "Coupling C = edges crossing the component boundary. $parent adds an implicit edge to an unnamed type.",
            ));
        }
        if l.contains("this.$root") || l.contains("$root.") {
            out.push(hit(
                "vue.root",
                Gate::Surgical,
                Severity::High,
                *n,
                1,
                t,
                "$root is a global mutable bag. You have reinvented a worse Redux.",
                "Pinia/store with typed actions. One write path.",
                "Globals destroy locality. Complexity is not the number of files, it is the number of unseen writers.",
            ));
        }
        if l.contains("this.items.push") || l.contains("this.props") && l.contains("=") || l.contains("mutate") {
            // handled below more precisely
        }
        if (l.contains("this.items.push")
            || l.contains("this.items.splice")
            || l.contains("this.items.pop")
            || (l.contains("this.") && l.contains(" = ") && l.contains("props")))
            && (src.raw.contains("props:") || src.raw.contains("defineProps") || src.raw.contains("props :"))
        {
            if l.contains("this.items") || l.contains("props") {
                out.push(hit(
                    "vue.mutate_prop",
                    Gate::Think,
                    Severity::High,
                    *n,
                    1,
                    t,
                    "Mutating a prop. Data flows down. You just created a two-way leak that Vue will warn about and then honor anyway.",
                    "Emit update:modelValue or copy into local ref on setup.",
                    "Props are read-only by contract. Mutation is an illegal write to the parent's state.",
                ));
            }
        }
        if l.contains("deep: true") || l.contains("deep:true") {
            out.push(hit(
                "vue.deep_watch",
                Gate::Simple,
                Severity::Med,
                *n,
                1,
                t,
                "deep:true watch on a large object is O(graph) every tick. You will not notice until a table of 2k rows.",
                "Watch a primitive or a computed scalar. If you need structural diff, do it explicitly.",
                "Deep watch cost ≈ |nodes| per reactive flush. That is not free.",
            ));
        }
        if l.contains("eval(") || l.contains("new function") {
            out.push(hit(
                "vue.eval",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "eval in a component is RCE if any input reaches it.",
                "Delete it.",
                "eval : String → ⊥.",
            ));
        }
        if l.contains("document.write") {
            out.push(hit(
                "vue.doc_write",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "document.write after load blows away the document. 1998 called.",
                "Delete it. Update a ref.",
                "document.write is a total function on the DOM identity. You do not want that.",
            ));
        }
        if l.contains("v-model") && l.contains("props.") {
            out.push(hit(
                "vue.vmodel_prop",
                Gate::Think,
                Severity::High,
                *n,
                1,
                t,
                "v-model on a prop field. Same as mutating props, with nicer syntax.",
                "Use a computed get/set that emits.",
                "v-model is syntactic sugar for write. Writes need an event, not a prop assignment.",
            ));
        }
        if l.contains("watch:") && l.contains("{") {
            // noisy
        }
        if l.contains("localstorage") && (l.contains("token") || l.contains("password") || l.contains("secret")) {
            out.push(hit(
                "vue.secret_storage",
                Gate::Think,
                Severity::Fatal,
                *n,
                1,
                t,
                "Secrets in localStorage are readable by any XSS on the origin. That is not storage, that is a drop box.",
                "HttpOnly cookie or memory + refresh. Never a bearer token in localStorage.",
                "XSS ⇒ origin-principal. localStorage ⊂ origin. Therefore XSS ⇒ token.",
            ));
        }
        if l.contains("any") && (l.contains(": any") || l.contains("as any")) {
            out.push(hit(
                "vue.as_any",
                Gate::Goal,
                Severity::Low,
                *n,
                1,
                t,
                "`as any` is a type-system skip_before_action. You opted out of the compiler.",
                "Type the object. If you cannot, you do not understand it yet — stop coding.",
                "any is the top type. Every check is vacuously true. Goal-driven: the type is the spec.",
            ));
        }
        if l.contains("future") && l.contains("flexib") || l.contains("just in case") {
            out.push(hit(
                "vue.speculative",
                Gate::Simple,
                Severity::Low,
                *n,
                1,
                t,
                "Speculative flexibility. Karpathy gate 2.",
                "Delete it until a test demands it.",
                "Yagni is not a vibe. It is expected value.",
            ));
        }
    }
    out
}

fn col(line: &str, needle: &str) -> usize {
    line.find(needle).map(|i| i + 1).unwrap_or(1)
}
