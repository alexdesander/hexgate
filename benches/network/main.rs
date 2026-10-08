// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! hexgate on simulated connections: every workload on every connection profile, each run with
//! a fresh server and client on localhost. Prints a report and writes it as text, JSON and CSV
//! to `target/netbench/`.
//!
//! ```text
//! cargo bench --bench network -- [--quick] [--duration SECS] [--drain SECS] [--seed N]
//!     [--profile NAME,..] [--workload NAME,..] [--out DIR] [--json] [--list]
//! ```

mod metrics;
mod report;
mod run;
mod workloads;

use std::{
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime},
};

use report::{Meta, Report};
use run::Settings;

struct Args {
    settings: Settings,
    profiles: Option<Vec<String>>,
    workloads: Option<Vec<String>>,
    out: PathBuf,
    json: bool,
    list: bool,
}

fn args() -> Args {
    let mut args = Args {
        settings: Settings {
            duration: Duration::from_secs(5),
            drain: Duration::from_secs(5),
            seed: 1,
        },
        profiles: None,
        workloads: None,
        out: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/netbench"),
        json: false,
        list: false,
    };
    let mut iter = std::env::args().skip(1);
    let secs = |value: Option<String>| {
        Duration::from_secs_f64(
            value
                .and_then(|v| v.parse().ok())
                .expect("seconds expected"),
        )
    };
    let names = |value: Option<String>| {
        Some(
            value
                .expect("names expected")
                .split(',')
                .map(str::to_owned)
                .collect(),
        )
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--quick" => {
                args.settings.duration = Duration::from_secs(2);
                args.settings.drain = Duration::from_secs(3);
            }
            "--duration" => args.settings.duration = secs(iter.next()),
            "--drain" => args.settings.drain = secs(iter.next()),
            "--seed" => {
                args.settings.seed = iter
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("number expected")
            }
            "--profile" => args.profiles = names(iter.next()),
            "--workload" => args.workloads = names(iter.next()),
            "--out" => args.out = iter.next().expect("directory expected").into(),
            "--json" => args.json = true,
            "--list" => args.list = true,
            // Added by `cargo bench`.
            "--bench" => {}
            other => panic!("unknown argument {other}, see the top of benches/network/main.rs"),
        }
    }
    args
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// `YYYY-MM-DD HH:MM UTC` (Howard Hinnant's civil-from-days).
fn utc(unix: u64) -> String {
    let days = (unix / 86400) as i64;
    let (hour, minute) = (unix % 86400 / 3600, unix % 3600 / 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

fn meta(settings: &Settings) -> Meta {
    let unix_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let commit = command("git", &["rev-parse", "--short", "HEAD"]).unwrap_or("unknown".into());
    let dirty = command("git", &["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("model name"))
                .map(|name| name.trim_start_matches([' ', '\t', ':']).to_owned())
        })
        .unwrap_or_else(|| std::env::consts::ARCH.into());
    Meta {
        commit: if dirty {
            format!("{commit}+dirty")
        } else {
            commit
        },
        date: utc(unix_time),
        unix_time,
        cpu,
        threads: std::thread::available_parallelism().map_or(1, usize::from),
        os: std::env::consts::OS,
        duration_s: settings.duration.as_secs_f64(),
        max_drain_s: settings.drain.as_secs_f64(),
        seed: settings.seed,
    }
}

fn main() {
    let args = args();
    let selected = |filter: &Option<Vec<String>>, name: &str| {
        filter
            .as_ref()
            .is_none_or(|names| names.iter().any(|n| n == name))
    };
    let profiles: Vec<_> = workloads::profiles()
        .into_iter()
        .filter(|(name, _)| selected(&args.profiles, name))
        .collect();
    let workloads: Vec<_> = workloads::workloads()
        .into_iter()
        .filter(|workload| selected(&args.workloads, workload.name))
        .collect();
    if args.list || profiles.is_empty() || workloads.is_empty() {
        println!("profiles:");
        for (name, _) in workloads::profiles() {
            println!("  {name}");
        }
        println!("workloads:");
        for workload in workloads::workloads() {
            println!(
                "  {:<15}{:<26}{}",
                workload.name, workload.category, workload.about
            );
        }
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("warning: debug build, use `cargo bench`");
    }

    run::now_us();
    let total = profiles.len() * workloads.len();
    let mut runs = Vec::with_capacity(total);
    let started = Instant::now();
    for workload in &workloads {
        for (name, profile) in &profiles {
            eprint!(
                "[{:>2}/{total}] {:<15} {:<9}",
                runs.len() + 1,
                workload.name,
                name
            );
            let start = Instant::now();
            let raw = run::run(workload, profile, &args.settings);
            let result = metrics::evaluate(workload, name, profile, raw);
            eprintln!(
                " {:>5.1} s{}",
                start.elapsed().as_secs_f64(),
                result
                    .error
                    .as_ref()
                    .map_or(String::new(), |error| format!("  ({error})"))
            );
            runs.push(result);
        }
    }
    eprintln!("done in {:.0} s", started.elapsed().as_secs_f64());

    let report = Report {
        meta: meta(&args.settings),
        profiles: profiles
            .iter()
            .map(|(name, profile)| report::profile_info(name, profile))
            .collect(),
        workloads: workloads.iter().map(report::workload_info).collect(),
        runs,
    };
    let text = report::text(&report, &workloads);
    let json = serde_json::to_string_pretty(&report).expect("serializable report");
    let csv = report::csv(&report);
    if args.json {
        println!("{json}");
    } else {
        print!("{text}");
    }

    let written = std::fs::create_dir_all(&args.out).and_then(|()| {
        let stamp = report.meta.unix_time;
        for (name, content) in [("txt", &text), ("json", &json), ("csv", &csv)] {
            std::fs::write(args.out.join(format!("{stamp}.{name}")), content)?;
            std::fs::write(args.out.join(format!("latest.{name}")), content)?;
        }
        Ok(())
    });
    match written {
        Ok(()) => eprintln!(
            "\nwritten to {}/latest.{{txt,json,csv}}",
            args.out.display()
        ),
        Err(e) => eprintln!(
            "\ncould not write the report to {}: {e}",
            args.out.display()
        ),
    }
}
