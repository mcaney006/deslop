use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use deslop::{analyze, Lang};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprint_help();
        return ExitCode::SUCCESS;
    }
    let json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");

    let mut lang = None;
    let mut path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "inspect" | "scan" | "check" => {}
            "--lang" | "-l" => {
                i += 1;
                lang = args.get(i).and_then(|s| Lang::parse(s));
            }
            s if s.starts_with("--lang=") => {
                lang = Lang::parse(&s[7..]);
            }
            s if !s.starts_with('-') => path = Some(PathBuf::from(s)),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let source = match &path {
        Some(p) if p.as_os_str() == "-" => slurp_stdin(),
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("read {}: {e}", p.display());
                return ExitCode::from(2);
            }
        },
        None => slurp_stdin(),
    };

    let lang = lang
        .or_else(|| path.as_ref().and_then(|p| infer(p)))
        .unwrap_or(Lang::Rails);

    let report = analyze(lang, &source);
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_human(&report);
    }

    if report.score.fatal > 0 {
        ExitCode::from(3)
    } else if report.score.deslop < 75 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn infer(p: &std::path::Path) -> Option<Lang> {
    match p.extension().and_then(|s| s.to_str()) {
        Some("rb") | Some("rake") => Some(Lang::Rails),
        Some("vue") | Some("js") | Some("ts") => Some(Lang::Vue),
        Some("sql") => Some(Lang::Sql),
        _ => None,
    }
}

fn slurp_stdin() -> String {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).ok();
    s
}

fn print_human(r: &deslop::Report) {
    println!("DESLOP  lang={}  lines={}  bytes={}", r.lang.as_str(), r.lines, r.bytes);
    println!(
        "score  deslop={}  think={}  simple={}  surgical={}  goal={}",
        r.score.deslop, r.score.think, r.score.simple, r.score.surgical, r.score.goal
    );
    println!("verdict  {}", r.verdict);
    println!();
    if r.findings.is_empty() {
        println!("(no findings)");
        return;
    }
    for f in &r.findings {
        println!(
            "L{:<4} {:<7} {:<8} {}",
            f.line,
            format!("{:?}", f.severity).to_lowercase(),
            f.gate.as_str(),
            f.id
        );
        println!("      {}", f.excerpt);
        println!("      WHY  {}", f.why);
        println!("      FIX  {}", f.fix);
        println!("      MATH {}", f.math);
        println!();
    }
}

fn eprint_help() {
    eprintln!(
        "deslop — the compiler does not forgive\n\n\
         USAGE:\n  deslop inspect [--lang rails|vue|sql] [--json] [FILE|-]\n\n\
         EXIT:\n  0 clean enough (>=75, no fatal)\n  1 slop\n  3 fatal\n  2 usage"
    );
}
