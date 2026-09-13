//! DESLOP — the compiler does not forgive.
//!
//! Karpathy's four behavioral gates, compiled into a deterministic analyzer
//! for Ruby on Rails, Vue SFCs, and SQL. No Python. No "best practices"
//! pamphlet. Hits are evidence: line, excerpt, gate, fix.

mod ast;
mod rails;
mod score;
mod sql;
mod vue;

use serde::{Deserialize, Serialize};

pub use ast::{AstKind, AstNode};
pub use score::{Gate, Score, Severity};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Rails,
    Vue,
    Sql,
}

impl Lang {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rails" | "rb" | "ruby" | "ror" => Some(Self::Rails),
            "vue" | "sfc" | "js" | "ts" => Some(Self::Vue),
            "sql" | "pg" | "postgres" | "redshift" => Some(Self::Sql),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rails => "rails",
            Self::Vue => "vue",
            Self::Sql => "sql",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub gate: Gate,
    pub severity: Severity,
    pub line: usize,
    pub column: usize,
    pub excerpt: String,
    pub why: String,
    pub fix: String,
    pub math: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub lang: Lang,
    pub bytes: usize,
    pub lines: usize,
    pub findings: Vec<Finding>,
    pub ast: Vec<AstNode>,
    pub score: Score,
    pub verdict: String,
}

#[derive(Clone, Debug)]
pub struct Src<'a> {
    pub raw: &'a str,
    pub lines: Vec<(usize, &'a str)>,
}

impl<'a> Src<'a> {
    pub fn new(raw: &'a str) -> Self {
        let lines = raw
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l))
            .collect();
        Self { raw, lines }
    }

    pub fn line(&self, n: usize) -> &str {
        self.lines
            .iter()
            .find(|(i, _)| *i == n)
            .map(|(_, s)| *s)
            .unwrap_or("")
    }
}

pub fn analyze(lang: Lang, source: &str) -> Report {
    let src = Src::new(source);
    let mut findings = match lang {
        Lang::Rails => rails::scan(&src),
        Lang::Vue => vue::scan(&src),
        Lang::Sql => sql::scan(&src),
    };
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(a.line.cmp(&b.line))
            .then(a.id.cmp(&b.id))
    });
    let ast = ast::build(lang, &src);
    let score = score::compute(&findings, src.lines.len());
    let verdict = score.verdict();
    Report {
        lang,
        bytes: source.len(),
        lines: src.lines.len(),
        findings,
        ast,
        score,
        verdict,
    }
}

pub fn analyze_json(lang: Lang, source: &str) -> String {
    serde_json::to_string(&analyze(lang, source)).expect("report serializes")
}

pub fn hit(
    id: &str,
    gate: Gate,
    severity: Severity,
    line: usize,
    column: usize,
    excerpt: &str,
    why: &str,
    fix: &str,
    math: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        gate,
        severity,
        line,
        column: column.max(1),
        excerpt: trim_ex(excerpt),
        why: why.to_string(),
        fix: fix.to_string(),
        math: math.to_string(),
    }
}

fn trim_ex(s: &str) -> String {
    let t = s.trim();
    if t.len() > 160 {
        format!("{}…", t.chars().take(159).collect::<String>())
    } else {
        t.to_string()
    }
}

/// C ABI for wasm32-unknown-unknown. JS allocates via `deslop_alloc`,
/// writes UTF-8, calls `deslop_analyze`, reads `deslop_out_ptr`/`len`.
#[cfg(target_arch = "wasm32")]
mod wasm_abi {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static OUT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    }

    #[no_mangle]
    pub extern "C" fn deslop_alloc(n: usize) -> *mut u8 {
        let mut v = Vec::with_capacity(n.saturating_add(1));
        v.resize(n, 0);
        let p = v.as_mut_ptr();
        std::mem::forget(v);
        p
    }

    #[no_mangle]
    pub extern "C" fn deslop_free(p: *mut u8, n: usize) {
        if p.is_null() {
            return;
        }
        unsafe {
            let _ = Vec::from_raw_parts(p, n, n);
        }
    }

    /// lang: 0 rails, 1 vue, 2 sql. Returns output byte length, or -1.
    #[no_mangle]
    pub extern "C" fn deslop_analyze(ptr: *const u8, len: usize, lang: u32) -> i32 {
        if ptr.is_null() {
            return -1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let src = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return -2,
        };
        let lang = match lang {
            0 => Lang::Rails,
            1 => Lang::Vue,
            2 => Lang::Sql,
            _ => return -3,
        };
        let json = analyze_json(lang, src);
        OUT.with(|o| {
            let mut o = o.borrow_mut();
            o.clear();
            o.extend_from_slice(json.as_bytes());
            o.len() as i32
        })
    }

    #[no_mangle]
    pub extern "C" fn deslop_out_ptr() -> *const u8 {
        OUT.with(|o| o.borrow().as_ptr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rails_n_plus_one_and_permit_bang() {
        let src = r#"
class LoadsController < ApplicationController
  skip_before_action :authenticate_user!
  def index
    Load.all.each do |load|
      load.carrier.name
      load.stops.first
    end
    User.find(params[:id])
    params.permit!
    render json: Load.all
  end
end
"#;
        let r = analyze(Lang::Rails, src);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"rails.n_plus_one"), "{ids:?}");
        assert!(ids.contains(&"rails.permit_bang"), "{ids:?}");
        assert!(ids.contains(&"rails.skip_auth"), "{ids:?}");
        assert!(ids.contains(&"rails.render_all"), "{ids:?}");
        assert!(r.score.deslop < 80);
    }

    #[test]
    fn vue_vhtml_and_vfor_key() {
        let src = r#"
<template>
  <div v-for="item in items" @click="onClick">
    <span v-html="item.body"></span>
  </div>
</template>
<script>
export default {
  props: ['items'],
  created() { this.items.push({}) },
  methods: {
    onClick() { this.$parent.reload() }
  }
}
</script>
"#;
        let r = analyze(Lang::Vue, src);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"vue.v_html"), "{ids:?}");
        assert!(ids.contains(&"vue.vfor_no_key"), "{ids:?}");
        assert!(ids.contains(&"vue.mutate_prop"), "{ids:?}");
        assert!(ids.contains(&"vue.parent"), "{ids:?}");
    }

    #[test]
    fn sql_select_star_and_unbounded_delete() {
        let src = r#"
SELECT * FROM loads l, carriers c
WHERE LOWER(l.mc_number) = '123456'
   OR 1=1;
DELETE FROM audit_events;
UPDATE loads SET status = 'void';
"#;
        let r = analyze(Lang::Sql, src);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"sql.select_star"), "{ids:?}");
        assert!(ids.contains(&"sql.comma_join"), "{ids:?}");
        assert!(ids.contains(&"sql.fn_on_column"), "{ids:?}");
        assert!(ids.contains(&"sql.tautology"), "{ids:?}");
        assert!(ids.contains(&"sql.unbounded_delete"), "{ids:?}");
        assert!(ids.contains(&"sql.unbounded_update"), "{ids:?}");
        assert!(r.score.deslop < 50);
    }

    #[test]
    fn clean_sql_scores_high() {
        let src = r#"
SELECT l.id, l.pro_number, c.legal_name
FROM loads l
INNER JOIN carriers c ON c.id = l.carrier_id
WHERE l.id = $1
  AND l.deleted_at IS NULL
LIMIT 1;
"#;
        let r = analyze(Lang::Sql, src);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert!(r.score.deslop >= 90);
    }
}
