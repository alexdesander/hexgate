// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The coexistence benchmark requires Linux network namespaces");
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use anyhow::{bail, Context};
    use hexgate::{
        client, error::SendError, server, Authenticator, Channel, ChannelConfiguration, Client,
        ClientVersion, SendOptions, SendOutcome, SendQueueLimits, Server, ServerKey,
    };
    use serde_json::{json, Value};
    use socket2::{Domain, Protocol, Socket, Type};

    const SECRET: [u8; 32] = [7; 32];
    const SNAPSHOT: Channel = Channel::Unreliable;
    const BULK: Channel = Channel::Reliable(0);
    const URGENT: Channel = Channel::Reliable(1);

    struct Accept;
    impl Authenticator<()> for Accept {
        fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
            Ok(())
        }
    }

    struct Settings {
        ip: String,
        start: u64,
        measure: u64,
        end: u64,
        stop: u64,
        cc: String,
        output: PathBuf,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    fn config() -> ChannelConfiguration {
        ChannelConfiguration {
            weights_reliable: vec![1, 1],
            ..Default::default()
        }
    }

    fn message(kind: u8, sequence: u64, size: usize, sent: u64) -> Vec<u8> {
        let mut data = vec![0; size];
        data[0] = kind;
        data[1..9].copy_from_slice(&sequence.to_le_bytes());
        data[9..17].copy_from_slice(&sent.to_le_bytes());
        data
    }

    pub fn run() -> anyhow::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 9 {
            bail!("coexist server|client IP START_US WARMUP_US DURATION_US DRAIN_US none|cubic|bbr OUTPUT");
        }
        let start: u64 = args[3].parse()?;
        let duration: u64 = args[5].parse()?;
        let settings = Settings {
            ip: args[2].clone(),
            start,
            measure: start + args[4].parse::<u64>()?,
            end: start + duration,
            stop: start + duration + args[6].parse::<u64>()?,
            cc: args[7].clone(),
            output: args[8].clone().into(),
        };
        let result = match args[1].as_str() {
            "server" => receive(&settings)?,
            "client" => send(&settings)?,
            _ => bail!("expected server or client"),
        };
        std::fs::write(settings.output, serde_json::to_vec_pretty(&result)?)?;
        Ok(())
    }

    fn receive(settings: &Settings) -> anyhow::Result<Value> {
        let server = Server::prepare()
            .bind_addr(format!("{}:4000", settings.ip).parse()?)
            .info(vec![])
            .allowed_client_versions(|_| Ok(()))
            .secret_key(SECRET)
            .auth_salt([0; 16])
            .authenticator(Accept)
            .channel_config(config())
            .close_linger(Duration::ZERO)
            .run()?;
        let tcp_bytes = Arc::new(AtomicU64::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let tcp = if settings.cc == "none" {
            None
        } else {
            let listener = TcpListener::bind(format!("{}:4001", settings.ip))?;
            listener.set_nonblocking(true)?;
            let bytes = tcp_bytes.clone();
            let stopping = stopping.clone();
            let (measure, end) = (settings.measure, settings.end);
            Some(thread::spawn(move || -> std::io::Result<()> {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopping.load(Ordering::Relaxed) {
                                return Ok(());
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                let mut buffer = [0; 65536];
                while !stopping.load(Ordering::Relaxed) {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(size) => {
                            if (measure..end).contains(&now()) {
                                bytes.fetch_add(size as u64, Ordering::Relaxed);
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }))
        };
        let mut snapshots = Vec::new();
        let mut urgent = Vec::new();
        let mut arrivals = Vec::new();
        let mut received = [0u64; 3];
        let mut bytes = [0u64; 3];
        let mut failures = Vec::new();
        while now() < settings.stop {
            match server.try_next() {
                Ok(Some(server::Event::Received(_, _, data))) if data.len() >= 17 => {
                    let at = now();
                    let kind = data[0] as usize;
                    if kind > 2 {
                        continue;
                    }
                    let sent = u64::from_le_bytes(data[9..17].try_into().unwrap());
                    if (settings.measure..settings.end).contains(&at) {
                        bytes[kind] += data.len() as u64;
                        if kind == 0 {
                            arrivals.push(at);
                        }
                    }
                    if (settings.measure..settings.end).contains(&sent) {
                        received[kind] += 1;
                        let latency = at.saturating_sub(sent) as f64 / 1000.0;
                        match kind {
                            0 => snapshots.push(latency),
                            1 => urgent.push(latency),
                            _ => {}
                        }
                    }
                }
                Ok(Some(server::Event::Violation(_, violation))) => {
                    failures.push(violation.to_string())
                }
                Ok(Some(server::Event::TimedOut(_))) => failures.push("timed out".into()),
                Ok(Some(_)) => {}
                Ok(None) => thread::sleep(Duration::from_micros(200)),
                Err(error) => {
                    failures.push(error.to_string());
                    break;
                }
            }
        }
        stopping.store(true, Ordering::Relaxed);
        if let Some(tcp) = tcp {
            tcp.join().unwrap()?;
        }
        let mut previous = settings.measure;
        let mut gap = 0;
        for arrival in arrivals {
            gap = gap.max(arrival.saturating_sub(previous));
            previous = arrival;
        }
        gap = gap.max(settings.end.saturating_sub(previous));
        let seconds = (settings.end - settings.measure) as f64 / 1e6;
        Ok(json!({
            "seconds": seconds, "received": received,
            "goodput_bytes_per_second": bytes.map(|bytes| bytes as f64 / seconds),
            "tcp_goodput_bytes_per_second": tcp_bytes.load(Ordering::Relaxed) as f64 / seconds,
            "snapshot_latency_ms": percentiles(snapshots), "urgent_latency_ms": percentiles(urgent),
            "snapshot_max_gap_ms": gap as f64 / 1000.0, "failures": failures,
        }))
    }

    fn percentiles(mut values: Vec<f64>) -> Value {
        if values.is_empty() {
            return Value::Null;
        }
        values.sort_unstable_by(f64::total_cmp);
        let at = |fraction: f64| values[((values.len() - 1) as f64 * fraction).round() as usize];
        json!({"p50": at(0.5), "p95": at(0.95), "p99": at(0.99), "max": at(1.0)})
    }

    fn tcp_sender(
        settings: &Settings,
    ) -> anyhow::Result<Option<thread::JoinHandle<std::io::Result<()>>>> {
        if settings.cc == "none" {
            return Ok(None);
        }
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_tcp_congestion(settings.cc.as_bytes())?;
        let actual = socket.tcp_congestion()?;
        anyhow::ensure!(
            actual.split(|byte| *byte == 0).next() == Some(settings.cc.as_bytes()),
            "unexpected TCP controller: {actual:?}"
        );
        socket.set_send_buffer_size(128 << 10)?;
        socket.connect(
            &format!("{}:4001", settings.ip)
                .parse::<SocketAddr>()?
                .into(),
        )?;
        let mut stream: TcpStream = socket.into();
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        let (start, end) = (settings.start, settings.end);
        Ok(Some(thread::spawn(move || {
            let buffer = [0; 65536];
            while now() < start {
                thread::sleep(Duration::from_millis(1));
            }
            while now() < end {
                match stream.write(&buffer) {
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })))
    }

    fn send(settings: &Settings) -> anyhow::Result<Value> {
        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(format!("{}:4000", settings.ip))
            .server_key(ServerKey::Pinned(server::public_key(&SECRET)))
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(config())
            .send_queue_limits(SendQueueLimits {
                max_bytes: 512 << 10,
                max_channel_bytes: 256 << 10,
                ..Default::default()
            })
            .close_linger(Duration::ZERO)
            .connect()
            .context("Hexgate handshake")?;
        client.set_priority(SNAPSHOT, 10)?;
        client.set_priority(URGENT, 10)?;
        client.set_priority(BULK, -1)?;
        let tcp = tcp_sender(settings)?;
        let mut next = [settings.start; 3];
        let intervals = [15625, 100000, 1000];
        let sizes = [800, 64, 16384];
        let channels = [SNAPSHOT, URGENT, BULK];
        let mut sequence = [0; 3];
        let mut offered = [0u64; 3];
        let mut admitted = [0u64; 3];
        let mut backpressured = [0u64; 3];
        let mut feedback = [0u64; 2];
        let mut failures = Vec::new();
        while now() < settings.stop {
            let at = now();
            if at < settings.end {
                for kind in 0..3 {
                    if at < next[kind] {
                        continue;
                    }
                    let measured = at >= settings.measure;
                    offered[kind] += u64::from(measured);
                    let options = SendOptions {
                        receipt: (kind == 0 && measured).then_some(sequence[kind]),
                        ..Default::default()
                    };
                    match client.send_with(
                        channels[kind],
                        message(kind as u8, sequence[kind], sizes[kind], at),
                        options,
                    ) {
                        Ok(()) => admitted[kind] += u64::from(measured),
                        Err(SendError::Backpressure) => backpressured[kind] += u64::from(measured),
                        Err(error) => {
                            failures.push(error.to_string());
                            break;
                        }
                    }
                    sequence[kind] += 1;
                    next[kind] += intervals[kind];
                }
            }
            loop {
                match client.try_next() {
                    Ok(Some(client::Event::SendResult(_, outcome))) => {
                        feedback[usize::from(outcome == SendOutcome::Dropped)] += 1
                    }
                    Ok(Some(client::Event::TimedOut)) => failures.push("timed out".into()),
                    Ok(Some(client::Event::Violation(violation))) => {
                        failures.push(violation.to_string())
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        failures.push(error.to_string());
                        break;
                    }
                }
            }
            if !failures.is_empty() {
                break;
            }
            thread::sleep(Duration::from_micros(200));
        }
        if let Some(tcp) = tcp {
            tcp.join().unwrap()?;
        }
        let stats = client.stats();
        Ok(json!({
            "offered": offered, "admitted": admitted, "backpressured": backpressured,
            "snapshot_acked": feedback[0], "snapshot_dropped": feedback[1],
            "queued_bytes": stats.as_ref().map(|stats| stats.queued_bytes), "failures": failures,
        }))
    }
}
