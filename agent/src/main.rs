use agent::{Codec, Message, Reader};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use sysinfo::{CpuRefreshKind, RefreshKind};

struct Timer {
    start: std::time::Instant,
    duration: std::time::Duration,
}

impl Timer {
    fn new(duration: std::time::Duration) -> Self {
        Self {
            start: std::time::Instant::now(),
            duration,
        }
    }

    fn is_expired(&self) -> bool {
        self.start.elapsed() >= self.duration
    }

    fn reset(&mut self) {
        self.start = std::time::Instant::now();
    }

    fn sleep(&self) {
        std::thread::sleep(self.duration - self.start.elapsed());
    }
}

fn main() -> std::io::Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:2749")?;
    // this supports only one connection.
    // if the firewall is configured properly, only the proxy can connect from a local machine
    // and therefor implementing multi-client support is useless
    // this protocol is designed for lan networks (as proxy servers mostly operate on them)
    // and so assumes packet loss is near 0%

    loop {
        udp.set_nonblocking(false)?;
        let (peer, msg) = get_msg(&udp)?;
        let Message::Connect = msg else {
            eprintln!("Message Not According to Protocol! Aborting");
            continue;
        };
        println!("New connection from {}", peer);
        handle_peer_session(&udp, peer)?
    }
}

fn get_msg(udp: &UdpSocket) -> std::io::Result<(SocketAddr, Message)> {
    let mut bytes = [0; 5]; // max msg size is 5 (1 for typ + 4 for metrics msg)
    let (used, peer) = udp.recv_from(&mut bytes)?;
    let mut reader = Reader::from(&bytes[..used]);
    let msg = match Message::read(&mut reader) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("Message Not According to Protocol! Aborting");
            return Err(ErrorKind::InvalidData.into());
        }
    };
    Ok((peer, msg))
}

fn handle_peer_session(udp: &UdpSocket, peer: SocketAddr) -> std::io::Result<()> {
    udp.set_nonblocking(true)?;
    send_ack(&udp, peer)?;

    let mut system = sysinfo::System::new_with_specifics(
        RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing().with_cpu_usage()),
    );
    const MAX_RETRY: usize = 3;
    let mut retry_count = 0;

    let mut timer = Timer::new(std::time::Duration::from_secs(5));

    loop {
        if timer.is_expired() {
            system.refresh_cpu_usage();
            let cpu = system.global_cpu_usage();
            let msg = Message::Metrics(agent::Metrics { cpu });
            let mut vec = Vec::with_capacity(5);
            msg.encode(&mut vec);
            udp.send_to(&vec, &peer)?;
            timer.reset();
            retry_count += 1;
            if retry_count > MAX_RETRY {
                eprintln!(
                    "No ACK received after {} retries. Disconnecting.",
                    MAX_RETRY
                );
                send_ack(&udp, peer)?;
                return Ok(());
            }
        }

        let (_peer, msg) = match get_msg(udp) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    timer.sleep();
                    continue;
                } else {
                    eprintln!("Error receiving message: {}", e);
                    return Err(e);
                }
            }
        };

        if _peer != peer {
            eprintln!("Another peer tried to connect. Ignoring");
            continue;
        }

        match msg {
            Message::Connect => {
                println!("Ignore new connection");
            }
            Message::Disconnect => {
                send_ack(&udp, peer)?;
                return Ok(());
            }
            Message::Ack => {
                retry_count = 0;
            }
            _ => {
                eprintln!("Message Not According to Protocol! Aborting");
                return Ok(());
            }
        }
    }
}

fn send_ack(socket: &UdpSocket, addr: SocketAddr) -> std::io::Result<()> {
    let mut vec = Vec::with_capacity(1);
    Message::Ack.encode(&mut vec);
    socket.send_to(&vec, &addr).map(|_| ()) // partial writes until i32::MAX not possible
}
