mod sniffer;
mod cryptography;
mod utils;

use std::fmt::{Debug, Formatter};
use std::thread;
use serde::{Deserialize, Serialize};

use anyhow::Result;
use crossbeam_channel::Sender;
use log::{error, trace};

#[cfg(feature = "tokio")]
use tokio::sync::mpsc::UnboundedSender as AsyncSender;
#[cfg(feature = "tokio")]
use tokio::runtime::Handle;

struct CrossbeamSender {
    sender: Sender<GamePacket>
}

impl PacketSender for CrossbeamSender {
    fn send(&self, data: GamePacket) {
        self.sender.send(data).unwrap()
    }
}

#[cfg(feature = "tokio")]
struct TokioSender {
    sender: AsyncSender<GamePacket>
}

#[cfg(feature = "tokio")]
impl PacketSender for TokioSender {
    fn send(&self, data: GamePacket) {
        _ = Handle::current().block_on(async {
            self.sender.send(data)
        });
    }
}

/// Sniffs game packets from the network using `pcap`.
///
/// If an error occurs while configuring the packet sniffer,
/// it will be thrown in the `Result`.
///
/// # Examples
///
/// ```rust,no_run
/// use ys_sniffer::Config;
///
/// fn main() -> anyhow::Result<()> {
///     let (tx, rx) = crossbeam_channel::unbounded();
///     let shutdown_hook = ys_sniffer::sniff(Config::default(), tx)?;
///
///     // To stop the sniffer, send a message to the shutdown hook.
///     shutdown_hook.send(())?;
///
///     Ok(())
/// }
/// ```
pub fn sniff(
    config: Config,
    consumer: Sender<GamePacket>
) -> Result<Sender<()>> {
    trace!("Configuration to be used: {:#?}", config);

    // Create shutdown hook.
    let (tx, rx) = crossbeam_channel::bounded(1);
    
    // Create the packet sender.
    let consumer = CrossbeamSender { sender: consumer };

    // Run the packet sniffer.
    thread::spawn(|| {
        if let Err(error) = sniffer::run(config, rx, consumer) {
            error!("Failed to run the sniffer: {:#?}", error);
        }
    });

    Ok(tx)
}

/// Sniffs game packets from the network using `pcap`.
///
/// If an error occurs while configuring the packet sniffer,
/// it will be thrown in the `Result`.
/// 
/// This requires a Tokio MPSC unbounded channel.
///
/// # Examples
///
/// ```rust,no_run
/// use ys_sniffer::Config;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
///     let shutdown_hook = ys_sniffer::sniff_async(Config::default(), tx).await?;
///
///     // To stop the sniffer, send a message to the shutdown hook.
///     shutdown_hook.send(())?;
///
///     Ok(())
/// }
/// ```
#[cfg(feature = "tokio")]
pub fn sniff_async(
    config: Config,
    consumer: AsyncSender<GamePacket>
) -> Result<Sender<()>> {
    trace!("Configuration to be used: {:#?}", config);

    // Create shutdown hook.
    let (tx, rx) = crossbeam_channel::bounded(1);

    // Create the packet sender.
    let consumer = TokioSender { sender: consumer };
    
    // Run the packet sniffer.
    thread::spawn(|| {
        if let Err(error) = sniffer::run(config, rx, consumer) {
            error!("Failed to run the sniffer: {:#?}", error);
        }
    });

    Ok(tx)
}

/// Represents a processed game packet.
#[derive(Clone, Debug)]
pub struct GamePacket {
    pub id: u16,
    pub header: Vec<u8>,
    pub data: Vec<u8>,
    pub source: PacketSource
}

impl Default for GamePacket {
    fn default() -> Self {
        GamePacket {
            id: 0,
            header: vec![],
            data: vec![],
            source: PacketSource::Server
        }
    }
}

/// Represents the source of a packet.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum PacketSource {
    /// This packet was sent by the client.
    ///
    /// Common names include: `<name>Req`, `<name>Notify`, `<name>C2S<side>`
    Client,

    /// This packet was sent by the server.
    ///
    /// Common names include: `<name>Rsp`, `<name>Notify`, `<name>S2C<side>`
    Server
}

impl PacketSource {
    /// Determines the packet source based on the configuration and port.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use ys_sniffer::{PacketSource, Config};
    ///
    /// let config = Config {
    ///     server_port: vec![22101, 22102],
    ///     ..Default::default()
    /// };
    ///
    /// let result = PacketSource::from(&config, 22101);
    /// assert_eq!(result, PacketSource::Server);
    /// ```
    pub fn from(config: &Config, port: u16) -> PacketSource {
        if config.server_port.contains(&port) {
            PacketSource::Server
        } else {
            PacketSource::Client
        }
    }

    /// Simple utility method to determine if the packet is from the client.
    pub fn is_client(&self) -> bool {
        self.eq(&PacketSource::Client)
    }

    /// Simple utility method to determine if the packet is from the server.
    pub fn is_server(&self) -> bool {
        self.eq(&PacketSource::Server)
    }
}

impl Debug for PacketSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketSource::Client => write!(f, "Client"),
            PacketSource::Server => write!(f, "Server")
        }
    }
}

/// Configuration used for the sniffer.
///
/// This does not include any programmable logic.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Config {
    /// This is the name of the capturing device to use.
    /// The name can be found with `pcap_findalldevs`.
    ///
    /// When left blank, the first active device is used.
    pub device_name: Option<String>,

    /// This is the filter to apply to the capture device.
    /// A blank filter can result in the program receiving more traffic than necessary.
    ///
    /// When left blank, no filter is applied.
    ///
    /// # Default
    ///
    /// `udp portrange 22101-22102`
    pub filter: Option<String>,

    /// A list of ports which the server listens for traffic on.
    /// This is used for determining if a packet is incoming or outgoing.
    ///
    /// This cannot be left blank.
    ///
    /// # Default
    ///
    /// `[22101, 22102]`
    pub server_port: Vec<u16>,

    /// The path to a file containing known seeds.
    /// The specific path needs to be readable and writable.
    ///
    /// This cannot be left blank.
    ///
    /// # Default
    ///
    /// `known_seeds.txt`
    pub known_seeds: String
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_name: None,
            filter: Some("udp portrange 22101-22102".to_string()),
            server_port: vec![22101, 22102],
            known_seeds: "known_seeds.txt".to_string()
        }
    }
}

// If the feature is enabled, include the `processor` module.
#[cfg(feature = "processor")]
pub use sniffer::Processor;
use crate::sniffer::PacketSender;