// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use crossbeam::channel::{Receiver, RecvTimeoutError};

use crate::common::timed_event_queue::TimedEventQueue;

/// This trait is used to simulate network conditions.
/// This is useful for testing your application under different network conditions.
///
/// You can only simulate SENDING packets, not receiving them.
/// To work around this, just configure a network simulator on both the client and the server.
pub trait NetworkSimulator: Send {
    /// This is called when a packet is being sent.
    /// The return value is:
    /// - None: The packet will be dropped (to simulate network unreliability).
    /// - Some(Duration): The packet will be delayed by this duration before being sent (to simulate network delay and reordering).
    ///
    /// PERFORMANCE: This spins up a dedicated thread to do the sending of packets. This is (for obvious reasons) a lot of overhead.
    fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<Duration>;
}

pub(crate) enum SimulatorThreadCmd {
    ChangeSimulator(Box<dyn NetworkSimulator>),
    Send(SocketAddr, Vec<u8>),
    Shutdown,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum EventKey {
    Send(u64),
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Send(SocketAddr, Vec<u8>),
}

pub(crate) fn simulator_thread(
    cmds: Receiver<SimulatorThreadCmd>,
    socket: UdpSocket,
    mut simulator: Box<dyn NetworkSimulator>,
) {
    let mut timed_events: TimedEventQueue<EventKey, Event> = TimedEventQueue::new();
    let mut send_key_counter = 0;
    loop {
        let cmd = if let Some(deadline) = timed_events.next() {
            if deadline.elapsed() > Duration::ZERO {
                let (_key, event) = timed_events.pop().unwrap();
                match event {
                    Event::Send(socket_addr, packet) => {
                        match socket.send_to(&packet, socket_addr) {
                            Ok(size) => assert_eq!(size, packet.len()),
                            Err(e) => {
                                todo!("Handle send errors in simulator_thread: {:?}", e);
                            }
                        }
                    }
                }
                continue;
            }
            match cmds.recv_deadline(deadline) {
                Ok(cmd) => cmd,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match cmds.recv() {
                Ok(cmd) => cmd,
                Err(_) => break,
            }
        };
        match cmd {
            SimulatorThreadCmd::ChangeSimulator(new_simulator) => {
                simulator = new_simulator;
            }
            SimulatorThreadCmd::Send(socket_addr, packet) => {
                if let Some(delay) = simulator.simulate(socket_addr, packet.len()) {
                    timed_events.push(
                        EventKey::Send(send_key_counter),
                        Instant::now() + delay,
                        Event::Send(socket_addr, packet),
                    );
                    send_key_counter += 1;
                }
            }
            SimulatorThreadCmd::Shutdown => break,
        }
    }
}
