use serde::{Deserialize, Serialize};

use crate::{Lang, Src};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AstKind {
    Module,
    Class,
    Method,
    Call,
    Block,
    Template,
    Script,
    Style,
    Directive,
    Select,
    From,
    Join,
    Where,
    Dml,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstNode {
    pub kind: AstKind,
    pub name: String,
    pub line: usize,
    pub depth: usize,
}

pub fn build(lang: Lang, src: &Src<'_>) -> Vec<AstNode> {
    match lang {
        Lang::Rails => rails_ast(src),
        Lang::Vue => vue_ast(src),
        Lang::Sql => sql_ast(src),
    }
}

fn rails_ast(src: &Src<'_>) -> Vec<AstNode> {
    let mut out = Vec::new();
    for (n, line) in &src.lines {
        let t = line.trim();
        let depth = line.len().saturating_sub(line.trim_start().len()) / 2;
        if let Some(rest) = t.strip_prefix("class ") {
            let name = rest.split_whitespace().next().unwrap_or("?").to_string();
            out.push(node(AstKind::Class, name, *n, depth));
        } else if let Some(rest) = t.strip_prefix("module ") {
            let name = rest.split_whitespace().next().unwrap_or("?").to_string();
            out.push(node(AstKind::Module, name, *n, depth));
        } else if let Some(rest) = t.strip_prefix("def ") {
            let name = rest.split(|c: char| c == '(' || c.is_whitespace()).next().unwrap_or("?").to_string();
            out.push(node(AstKind::Method, name, *n, depth));
        } else if t.contains(" do |") || t.ends_with(" do") {
            out.push(node(AstKind::Block, t.chars().take(48).collect(), *n, depth));
        }
    }
    out
}

fn vue_ast(src: &Src<'_>) -> Vec<AstNode> {
    let mut out = Vec::new();
    for (n, line) in &src.lines {
        let t = line.trim();
        let depth = line.len().saturating_sub(line.trim_start().len()) / 2;
        if t.starts_with("<template") {
            out.push(node(AstKind::Template, "template".into(), *n, depth));
        } else if t.starts_with("<script") {
            out.push(node(AstKind::Script, "script".into(), *n, depth));
        } else if t.starts_with("<style") {
            out.push(node(AstKind::Style, "style".into(), *n, depth));
        } else if let Some(d) = vue_dir(t) {
            out.push(node(AstKind::Directive, d, *n, depth));
        }
    }
    out
}

fn vue_dir(t: &str) -> Option<String> {
    for d in ["v-html", "v-for", "v-if", "v-else", "v-model", "v-show", "v-bind", "v-on"] {
        if t.contains(d) {
            return Some(d.into());
        }
    }
    None
}

fn sql_ast(src: &Src<'_>) -> Vec<AstNode> {
    let mut out = Vec::new();
    for (n, line) in &src.lines {
        let u = line.trim().to_ascii_uppercase();
        let depth = line.len().saturating_sub(line.trim_start().len()) / 2;
        if u.starts_with("WITH ") {
            out.push(node(AstKind::Select, "cte".into(), *n, depth));
        } else if u.starts_with("SELECT") {
            out.push(node(AstKind::Select, "select".into(), *n, depth));
        } else if u.starts_with("FROM") {
            out.push(node(AstKind::From, clip(line), *n, depth));
        } else if u.contains(" JOIN ") || u.starts_with("JOIN ") {
            out.push(node(AstKind::Join, clip(line), *n, depth));
        } else if u.starts_with("WHERE") {
            out.push(node(AstKind::Where, clip(line), *n, depth));
        } else if u.starts_with("DELETE") || u.starts_with("UPDATE") || u.starts_with("INSERT") {
            out.push(node(AstKind::Dml, clip(line), *n, depth));
        }
    }
    out
}

fn clip(s: &str) -> String {
    s.trim().chars().take(64).collect()
}

fn node(kind: AstKind, name: String, line: usize, depth: usize) -> AstNode {
    AstNode {
        kind,
        name,
        line,
        depth,
    }
}
