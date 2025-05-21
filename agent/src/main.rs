use agent::{Codec, Message, Reader};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use sysinfo::{CpuRefreshKind, RefreshKind};


/// Represents a timer that tracks elapsed time since a starting point
/// up to a specified duration.
///
/// # Fields
///
/// * `start`: The `std::time::Instant` when the timer was initiated.
/// * `duration`: The `std::time::Duration` for which the timer is set.
struct Timer {
    start: std::time::Instant,
    duration: std::time::Duration,
}


/// Implements a simple timer functionality.
///
/// `Timer` can be used to track elapsed time, check if a certain duration
/// has passed, reset the timer, or pause execution for the remaining duration.
impl Timer {
    /// Creates a new `Timer` instance.
    ///
    /// # Arguments
    ///
    /// * `duration`: A `std::time::Duration` specifying the total duration for this timer.
    ///
    /// # Returns
    ///
    /// A new `Timer` instance, initialized with the current time as the starting point
    /// and the specified `duration`.
    fn new(duration: std::time::Duration) -> Self {
        Self {
            start: std::time::Instant::now(),
            duration,
        }
    }

    /// Checks if the timer has expired.
    ///
    /// # Returns
    ///
    /// `true` if the elapsed time since the timer started or was last reset
    /// is greater than or equal to its `duration`, `false` otherwise.
    fn is_expired(&self) -> bool {
        self.start.elapsed() >= self.duration
    }

    /// Resets the timer.
    ///
    /// This sets the timer's start time to the current `std::time::Instant::now()`,
    /// effectively restarting the countdown. The original `duration` remains unchanged.
    fn reset(&mut self) {
        self.start = std::time::Instant::now();
    }

    /// Pauses the current thread's execution until the timer expires.
    ///
    /// This function calculates the remaining time and sleeps for that duration.
    /// If the timer has already expired, this function will attempt to sleep for
    /// a zero or negative duration, which `std::thread::sleep` typically handles
    /// by returning immediately.
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

/// Reads a message from the UDP socket.
///
/// # Arguments
///
/// * `udp`: A reference to the `UdpSocket` from which to read the message.
///
/// # Returns
///
/// * `Ok((SocketAddr, Message))`: A tuple containing the address of the peer and the decoded message.
/// * `Err(std::io::Error)`: An error if the message could not be read or decoded.
///
/// # Errors
///
/// * `std::io::ErrorKind::InvalidData`: If the message does not conform to the expected protocol.
///
/// # Example
///
/// ```
/// let (peer, msg) = get_msg(&udp)?;
/// if let Message::Connect = msg {
///     println!("New connection from {}", peer);
/// }
///```
/// # Note
/// This function assumes that the message is at most 5 bytes long (1 byte for type + 4 bytes for metrics).
/// If the message is longer, it will be truncated to 5 bytes.
/// The function also sets the socket to non-blocking mode, allowing it to handle multiple connections
/// without blocking on a single read operation.
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

/// Handles a peer session.
///
/// This function is responsible for managing the communication with a connected peer.
/// It sends an acknowledgment message, monitors the CPU usage, and handles incoming messages.
/// If a disconnect message is received, it will send an acknowledgment and terminate the session.
/// If no acknowledgment is received after a certain number of retries, it will also terminate the session.
///
/// # Arguments
///
/// * `udp`: A reference to the `UdpSocket` used for communication.
/// * `peer`: The address of the connected peer.
///
/// # Returns
///
///
/// * `Ok(())`: If the session was handled successfully.
/// * `Err(std::io::Error)`: If there was an error during communication.
///
fn handle_peer_session(udp: &UdpSocket, peer: SocketAddr) -> std::io::Result<()> {
    udp.set_nonblocking(true)?;
    send_ack(&udp, peer)?;

    let mut system = sysinfo::System::new_with_specifics(
        RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing().with_cpu_usage()),
    );
    /// The maximum number of retries for sending the acknowledgment.
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

/// Sends an acknowledgment message to the specified address.
///
/// This function encodes an `Ack` message into a vector and sends it
/// to the given `SocketAddr` using the provided `UdpSocket`.
///
/// # Arguments
///
/// * `socket`: A reference to the `UdpSocket` used for sending the message.
/// * `addr`: The `SocketAddr` of the recipient.
///
/// # Returns
///
/// * `Ok(())`: If the acknowledgment was sent successfully.
/// * `Err(std::io::Error)`: If there was an error during sending.
fn send_ack(socket: &UdpSocket, addr: SocketAddr) -> std::io::Result<()> {
    let mut vec = Vec::with_capacity(1);
    Message::Ack.encode(&mut vec);
    socket.send_to(&vec, &addr).map(|_| ()) // partial writes until i32::MAX not possible
}
