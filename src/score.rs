use serde::{Deserialize, Serialize};

use crate::Finding;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    Think,
    Simple,
    Surgical,
    Goal,
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Think => "think",
            Self::Simple => "simple",
            Self::Surgical => "surgical",
            Self::Goal => "goal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Fatal,
    High,
    Med,
    Low,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Fatal => 4,
            Self::High => 3,
            Self::Med => 2,
            Self::Low => 1,
        }
    }
    pub fn weight(self) -> i32 {
        match self {
            Self::Fatal => 28,
            Self::High => 14,
            Self::Med => 7,
            Self::Low => 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Score {
    pub think: u8,
    pub simple: u8,
    pub surgical: u8,
    pub goal: u8,
    pub deslop: u8,
    pub fatal: usize,
    pub high: usize,
    pub med: usize,
    pub low: usize,
}

impl Score {
    pub fn verdict(&self) -> String {
        match self.deslop {
            90..=255 => "CLEAN. The compiler nods.".into(),
            75..=89 => "MOSTLY HONEST. Residual slop. Cut it.".into(),
            50..=74 => "SLOP DETECTED. Do not ship.".into(),
            25..=49 => "VIBE CODING. This will page you at 02:00.".into(),
            _ => "APOSTASY. Rewrite from the AST up.".into(),
        }
    }
}

/// Score model:
///   gate_i = clamp(100 - Σ weight(severity) for findings of gate_i)
///   deslop = 0.30 think + 0.25 simple + 0.20 surgical + 0.25 goal
/// Empty file is not a 100 — it is untestable. Floor by line count.
pub fn compute(findings: &[Finding], lines: usize) -> Score {
    let mut think_pen = 0;
    let mut simple_pen = 0;
    let mut surgical_pen = 0;
    let mut goal_pen = 0;
    let mut fatal = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    for f in findings {
        let w = f.severity.weight();
        match f.gate {
            Gate::Think => think_pen += w,
            Gate::Simple => simple_pen += w,
            Gate::Surgical => surgical_pen += w,
            Gate::Goal => goal_pen += w,
        }
        match f.severity {
            Severity::Fatal => fatal += 1,
            Severity::High => high += 1,
            Severity::Med => med += 1,
            Severity::Low => low += 1,
        }
    }
    let think = clamp100(100 - think_pen);
    let simple = clamp100(100 - simple_pen);
    let surgical = clamp100(100 - surgical_pen);
    let goal = clamp100(100 - goal_pen);
    let mut deslop = (0.30 * think as f64
        + 0.25 * simple as f64
        + 0.20 * surgical as f64
        + 0.25 * goal as f64)
        .round() as i32;
    if lines == 0 {
        deslop = 0;
    }
    if fatal > 0 {
        deslop = deslop.min(45);
    }
    Score {
        think,
        simple,
        surgical,
        goal,
        deslop: clamp100(deslop),
        fatal,
        high,
        med,
        low,
    }
}

fn clamp100(v: i32) -> u8 {
    v.clamp(0, 100) as u8
}
