// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The text report and the JSON and CSV files.

use std::fmt::Write;

use hexgate::sim::{JitterDistribution, LinkConfig, Profile};
use serde::Serialize;

use crate::{
    metrics::{channel_name, Percentiles, RunResult, StreamResult},
    workloads::Workload,
};

#[derive(Serialize)]
pub struct Report {
    pub meta: Meta,
    pub profiles: Vec<ProfileInfo>,
    pub workloads: Vec<WorkloadInfo>,
    pub runs: Vec<RunResult>,
}

#[derive(Serialize)]
pub struct Meta {
    pub commit: String,
    pub date: String,
    pub unix_time: u64,
    pub cpu: String,
    pub threads: usize,
    pub os: &'static str,
    pub duration_s: f64,
    pub max_drain_s: f64,
    pub seed: u64,
}

#[derive(Serialize)]
pub struct ProfileInfo {
    pub name: &'static str,
    pub base_rtt_ms: f64,
    pub jitter: String,
    pub loss: String,
    pub rate_mbit: String,
    pub buffer: String,
    pub extras: String,
    pub up: String,
    pub down: String,
}

#[derive(Serialize)]
pub struct WorkloadInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub about: &'static str,
    pub key: &'static str,
    pub streams: Vec<String>,
}

pub fn profile_info(name: &'static str, profile: &Profile) -> ProfileInfo {
    let link = &profile.down;
    let rate = |link: &LinkConfig| {
        link.bottleneck
            .as_ref()
            .map_or("unlimited".into(), |bottleneck| {
                let rate = |rate: u64| format!("{:.0}", rate as f64 * 8.0 / 1e6);
                if bottleneck.rates.len() > 1 {
                    let average = bottleneck
                        .rates
                        .iter()
                        .map(|(duration, rate)| duration.as_secs_f64() * *rate as f64)
                        .sum::<f64>()
                        / bottleneck
                            .rates
                            .iter()
                            .map(|(duration, _)| duration.as_secs_f64())
                            .sum::<f64>();
                    format!("~{:.1}", average * 8.0 / 1e6)
                } else {
                    rate(bottleneck.rates[0].1)
                }
            })
    };
    let mut extras = Vec::new();
    if let Some(spikes) = link.spikes {
        extras.push(format!("+{} ms spikes", spikes.extra.as_millis()));
    }
    if let Some(stalls) = link.stalls {
        extras.push(format!("{} ms stalls", stalls.duration.as_millis()));
    }
    if let Some(outages) = link.outages {
        extras.push(format!("{} ms outages", outages.duration.as_millis()));
    }
    if let Some(cross) = link
        .bottleneck
        .as_ref()
        .and_then(|bottleneck| bottleneck.cross_traffic)
    {
        extras.push(format!("{:.1} Mbit/s cross", cross.rate as f64 * 8.0 / 1e6));
    }
    if let Some(reorder) = link.reorder {
        extras.push(format!("reorder {:.1}%", reorder.probability * 100.0));
    }
    if let Some(duplicate) = link.duplicate {
        extras.push(format!("dup {:.1}%", duplicate.probability * 100.0));
    }
    if let Some(slot) = link.slot {
        extras.push(format!("slot {} ms", slot.as_millis()));
    }
    ProfileInfo {
        name,
        base_rtt_ms: profile.base_rtt().as_secs_f64() * 1000.0,
        jitter: link.jitter.map_or("-".into(), |jitter| {
            let distribution = match jitter.distribution {
                JitterDistribution::Uniform => "uniform",
                JitterDistribution::Normal => "normal",
                JitterDistribution::Exponential => "exp",
                JitterDistribution::Pareto => "pareto",
                JitterDistribution::ParetoNormal => "p-normal",
            };
            format!("{} ms {distribution}", jitter.mean.as_secs_f64() * 1000.0)
        }),
        loss: link.loss.map_or("-".into(), |loss| {
            let rate = if loss.p == 0.0 {
                loss.good
            } else {
                loss.p / (loss.p + loss.r) * loss.bad + loss.r / (loss.p + loss.r) * loss.good
            };
            if loss.p == 0.0 {
                format!("{:.1}% random", rate * 100.0)
            } else {
                format!("{:.1}% bursts of {:.0}", rate * 100.0, 1.0 / loss.r)
            }
        }),
        rate_mbit: format!("{} / {}", rate(&profile.down), rate(&profile.up)),
        buffer: link.bottleneck.as_ref().map_or("-".into(), |bottleneck| {
            let rate = bottleneck.rates[0].1 as f64;
            format!("{:.0} ms", bottleneck.buffer as f64 / rate * 1000.0)
        }),
        extras: if extras.is_empty() {
            "-".into()
        } else {
            extras.join(", ")
        },
        up: format!("{:?}", profile.up),
        down: format!("{:?}", profile.down),
    }
}

pub fn workload_info(workload: &Workload) -> WorkloadInfo {
    WorkloadInfo {
        name: workload.name,
        category: workload.category,
        about: workload.about,
        key: workload.key,
        streams: workload
            .streams
            .iter()
            .map(|stream| {
                format!(
                    "{} {:?} {} {:?}",
                    stream.name,
                    stream.dir,
                    channel_name(stream.channel),
                    stream.pattern
                )
            })
            .collect(),
    }
}

/// About 3 significant digits in 8 columns.
fn num(value: Option<f64>) -> String {
    match value {
        None => format!("{:>8}", "-"),
        Some(v) if v.abs() < 10.0 => format!("{v:>8.2}"),
        Some(v) if v.abs() < 100.0 => format!("{v:>8.1}"),
        Some(v) => format!("{v:>8.0}"),
    }
}

fn pick(latency: Option<Percentiles>, f: impl Fn(Percentiles) -> f64) -> Option<f64> {
    latency.map(f)
}

fn rule(out: &mut String, title: &str) {
    let width = 137usize.saturating_sub(title.chars().count());
    let _ = writeln!(out, "\n━━ {title} {}", "━".repeat(width));
}

pub fn text(report: &Report, workloads: &[Workload]) -> String {
    let mut out = String::new();
    let meta = &report.meta;
    let _ = writeln!(out, "hexgate network benchmark");
    let _ = writeln!(
        out,
        "commit {} · {} · {} · {} threads · {} s per run, drain <= {} s · seed {}",
        meta.commit,
        meta.date,
        meta.cpu,
        meta.threads,
        meta.duration_s,
        meta.max_drain_s,
        meta.seed
    );
    let _ = writeln!(
        out,
        "Latency: ms from send() to Received (round trip for ping streams). +p50/+p99: above the \
         profile's base delay.\nGoodput: Mbit/s of message bytes that arrived during the send \
         phase. Delivery: % of sent messages. * = key stream."
    );

    rule(&mut out, "profiles (down link; rates down / up)");
    let _ = writeln!(
        out,
        "{:<10}{:>9}  {:<16}{:<20}{:<22}{:>7}  extras",
        "profile", "base RTT", "jitter (mean)", "loss", "Mbit/s", "buffer"
    );
    for profile in &report.profiles {
        let _ = writeln!(
            out,
            "{:<10}{:>6} ms  {:<16}{:<20}{:<22}{:>7}  {}",
            profile.name,
            profile.base_rtt_ms,
            profile.jitter,
            profile.loss,
            profile.rate_mbit,
            profile.buffer,
            profile.extras
        );
    }

    for workload in workloads {
        let runs: Vec<&RunResult> = report
            .runs
            .iter()
            .filter(|run| run.workload == workload.name)
            .collect();
        if runs.is_empty() {
            continue;
        }
        rule(
            &mut out,
            &format!(
                "{} · {} · {}",
                workload.name, workload.category, workload.about
            ),
        );
        let _ = writeln!(
            out,
            "{:<9} {:<12}{:<5}{:<6}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}{:>8}",
            "profile", "stream", "dir", "chan", "deliv%", "min", "p50", "p90", "p99", "p99.9",
            "max", "+p50", "+p99", "jitter", "maxgap", "stall/m", "goodput"
        );
        for run in &runs {
            if !run.connected {
                let _ = writeln!(
                    out,
                    "{:<9} connect failed: {}",
                    run.profile,
                    run.error.as_deref().unwrap_or("?")
                );
                continue;
            }
            for (i, stream) in run.streams.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{}",
                    stream_row(if i == 0 { run.profile } else { "" }, stream)
                );
            }
        }
        let _ = writeln!(
            out,
            "{:<9} {:>10} {:>16} {:>16} {:>16} {:>9} {:>12} {:>6}  notes",
            "",
            "connect ms",
            "drops up %",
            "drops down %",
            "queue down ms",
            "rtt ms",
            "rate Mbit/s",
            "wire"
        );
        for run in runs.iter().filter(|run| run.connected) {
            let drops = |link: &crate::metrics::LinkSummary| {
                format!(
                    "{:.1} ({}/{}/{})",
                    link.drop_rate * 100.0,
                    link.lost,
                    link.lost_queue,
                    link.lost_outage
                )
            };
            let hexgate = run.server_stats.as_ref();
            let mut notes: Vec<String> = run
                .streams
                .iter()
                .filter_map(|stream| {
                    let bursts = stream.bursts.as_ref()?;
                    let completion = bursts.completion_ms?;
                    Some(format!(
                        "{} bursts {}/{} done, p50 {} p99 {} ms",
                        stream.name,
                        bursts.complete,
                        bursts.sent,
                        num(Some(completion.p50)).trim(),
                        num(Some(completion.p99)).trim()
                    ))
                })
                .collect();
            notes.extend(run.error.iter().map(|error| format!("ENDED: {error}")));
            notes.extend(run.streams.iter().flat_map(|stream| {
                stream
                    .violations
                    .iter()
                    .map(move |violation| format!("VIOLATION {}: {violation}", stream.name))
            }));
            let _ = writeln!(
                out,
                "{:<9} {:>10} {:>16} {:>16} {:>16} {:>9} {:>12} {:>6}  {}",
                run.profile,
                num(run.connect_ms).trim(),
                drops(&run.link_up),
                drops(&run.link_down),
                format!(
                    "{} / {}",
                    num(Some(run.link_down.mean_queue_ms)).trim(),
                    num(Some(run.link_down.max_queue_ms)).trim()
                ),
                num(hexgate.and_then(|stats| stats.rtt_ms)).trim(),
                hexgate.map_or("-".into(), |stats| format!("{:.1}", stats.send_rate_mbit)),
                run.wire_efficiency
                    .map_or("-".into(), |wire| format!("{:.0}%", wire * 100.0)),
                notes.join(" · ")
            );
        }
        let _ = writeln!(
            out,
            "{:<9} drops: % (loss/queue/outage packets) · queue: mean / max · rtt, rate: hexgate's \
             estimate and send rate (server) · wire: message bytes per datagram byte",
            ""
        );
    }

    summary(&mut out, report, workloads);
    out
}

fn stream_row(profile: &str, stream: &StreamResult) -> String {
    let latency = stream.latency_ms;
    let marker = if stream.key { "*" } else { " " };
    format!(
        "{:<9}{marker}{:<12}{:<5}{:<6}{:>8.1}{}{}{}{}{}{}{}{}{}{}{}{}",
        profile,
        stream.name,
        format!("{:?}", stream.dir).to_lowercase(),
        stream.channel,
        stream.delivery * 100.0,
        num(pick(latency, |l| l.min)),
        num(pick(latency, |l| l.p50)),
        num(pick(latency, |l| l.p90)),
        num(pick(latency, |l| l.p99)),
        num(pick(latency, |l| l.p999)),
        num(pick(latency, |l| l.max)),
        num(stream.added_ms.as_ref().map(|added| added.p50)),
        num(stream.added_ms.as_ref().map(|added| added.p99)),
        num(stream.jitter_ms),
        num(stream.max_gap_ms),
        num(stream.stalls_per_min),
        num(Some(stream.goodput_mbit)),
    )
}

fn summary(out: &mut String, report: &Report, workloads: &[Workload]) {
    let profiles: Vec<&str> = report.profiles.iter().map(|profile| profile.name).collect();
    let key = |workload: &str, profile: &str| {
        let run = report
            .runs
            .iter()
            .find(|run| run.workload == workload && run.profile == profile)?;
        Some((run, run.streams.iter().find(|stream| stream.key)?))
    };
    let matrix =
        |out: &mut String, title: &str, cell: &dyn Fn(&RunResult, &StreamResult) -> String| {
            rule(out, title);
            let _ = write!(out, "{:<26}", "workload (key stream)");
            for profile in &profiles {
                let _ = write!(out, "{profile:>20}");
            }
            let _ = writeln!(out);
            for workload in workloads {
                if !report.runs.iter().any(|run| run.workload == workload.name) {
                    continue;
                }
                let _ = write!(
                    out,
                    "{:<26}",
                    format!("{} ({})", workload.name, workload.key)
                );
                for profile in &profiles {
                    let value = match key(workload.name, profile) {
                        Some((run, stream)) if run.connected => cell(run, stream),
                        Some(_) => "no connect".into(),
                        None => "".into(),
                    };
                    let _ = write!(out, "{value:>20}");
                }
                let _ = writeln!(out);
            }
        };
    matrix(
        out,
        "summary: key stream latency p50 / p99 ms",
        &|_, stream| {
            stream.latency_ms.map_or("-".into(), |latency| {
                format!(
                    "{} / {}",
                    num(Some(latency.p50)).trim(),
                    num(Some(latency.p99)).trim()
                )
            })
        },
    );
    matrix(
        out,
        "summary: key stream added latency p99 ms (above base delay)",
        &|_, stream| {
            num(stream.added_ms.as_ref().map(|added| added.p99))
                .trim()
                .to_string()
        },
    );
    matrix(
        out,
        "summary: key stream delivery % · goodput Mbit/s",
        &|_, stream| format!("{:.1}% {:.2}", stream.delivery * 100.0, stream.goodput_mbit),
    );
    matrix(
        out,
        "summary: key stream stalls per min (gap > interval + 100 ms) · longest gap ms · bursts p99 ms",
        &|_, stream| match (stream.stalls_per_min, &stream.bursts) {
            (Some(stalls), _) => format!("{stalls:.1} · {}", num(stream.max_gap_ms).trim()),
            (None, Some(bursts)) => format!(
                "burst {}",
                num(bursts.completion_ms.map(|completion| completion.p99)).trim()
            ),
            _ => "-".into(),
        },
    );

    rule(out, "problems");
    let mut problems = 0;
    for run in &report.runs {
        if let Some(error) = &run.error {
            problems += 1;
            let _ = writeln!(out, "{} @ {}: {error}", run.workload, run.profile);
        }
        for stream in &run.streams {
            for violation in &stream.violations {
                problems += 1;
                let _ = writeln!(
                    out,
                    "{} @ {}: {} ({:?}): {violation}",
                    run.workload, run.profile, stream.name, stream.dir
                );
            }
            let reliable = stream.channel.starts_with("rel");
            if run.connected && reliable && !stream.round_trip && stream.delivered < stream.sent {
                problems += 1;
                let _ = writeln!(
                    out,
                    "{} @ {}: {} ({:?}): {} reliable messages still in flight after the drain",
                    run.workload,
                    run.profile,
                    stream.name,
                    stream.dir,
                    stream.sent - stream.delivered
                );
            }
        }
    }
    if problems == 0 {
        let _ = writeln!(
            out,
            "none: no failed connections, duplicates, corruption or reordering"
        );
    }
}

pub fn csv(report: &Report) -> String {
    let mut out = String::from(
        "workload,profile,stream,dir,channel,key,round_trip,sent,delivered,delivery,offered_mbit,\
         goodput_mbit,lat_min_ms,lat_p50_ms,lat_p90_ms,lat_p99_ms,lat_p999_ms,lat_max_ms,\
         lat_mean_ms,added_p50_ms,added_p99_ms,jitter_ms,max_gap_ms,stalls_per_min,\
         burst_p50_ms,burst_p99_ms,duplicates,reordered,corrupt,connected,connect_ms,\
         wire_efficiency,error\n",
    );
    let opt = |value: Option<f64>| value.map_or(String::new(), |value| format!("{value:.3}"));
    for run in &report.runs {
        for stream in &run.streams {
            let latency = stream.latency_ms;
            let burst = stream
                .bursts
                .as_ref()
                .and_then(|bursts| bursts.completion_ms);
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{:.5},{:.4},{:.4},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\"{}\"",
                run.workload,
                run.profile,
                stream.name,
                format!("{:?}", stream.dir).to_lowercase(),
                stream.channel,
                stream.key,
                stream.round_trip,
                stream.sent,
                stream.delivered,
                stream.delivery,
                stream.offered_mbit,
                stream.goodput_mbit,
                opt(pick(latency, |l| l.min)),
                opt(pick(latency, |l| l.p50)),
                opt(pick(latency, |l| l.p90)),
                opt(pick(latency, |l| l.p99)),
                opt(pick(latency, |l| l.p999)),
                opt(pick(latency, |l| l.max)),
                opt(pick(latency, |l| l.mean)),
                opt(stream.added_ms.as_ref().map(|added| added.p50)),
                opt(stream.added_ms.as_ref().map(|added| added.p99)),
                opt(stream.jitter_ms),
                opt(stream.max_gap_ms),
                opt(stream.stalls_per_min),
                opt(burst.map(|burst| burst.p50)),
                opt(burst.map(|burst| burst.p99)),
                stream.duplicates,
                stream.reordered,
                stream.corrupt,
                run.connected,
                opt(run.connect_ms),
                opt(run.wire_efficiency),
                run.error.as_deref().unwrap_or("").replace('"', "'"),
            );
        }
    }
    out
}
