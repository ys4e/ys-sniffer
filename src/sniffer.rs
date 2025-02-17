use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use crossbeam_channel::Receiver;
use pcap::{Capture, Device, Linktype, Packet};
use anyhow::{anyhow, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{error, trace, warn};
use bytes::BufMut;
use lazy_static::lazy_static;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use kcp::Kcp;
use protoshark::Value;
use crate::{cryptography, utils, Config, GamePacket, PacketSource};
use crate::cryptography::{Random, MT19937_64};

const CONNECT_CMD: u32 = 0xFF;
const CONV_CMD: u32 = 0x145;
const DISCONNECT_CMD: u32 = 0x194;

const KEYS: &str = include_str!("../resources/dispatch_keys.txt");
const RSA_KEY: &str = include_str!("../resources/private_key.pem");

lazy_static! {
    /// Load the hardcoded dispatch keys into memory.
    static ref DISPATCH_KEYS: HashMap<u16, Key> = {
        let mut keys = HashMap::new();
        for key in KEYS.lines() {
            let parts = key.split(": ").collect::<Vec<&str>>();
            let (first_byte, key) = match parts.as_slice() {
                [f, s] => (f, s),
                _ => panic!("Invalid key format.")
            };

            let first_byte = first_byte.parse::<u16>().unwrap();
            let mut key_bytes = [0u8; 4096];

            let mut i = 0;
            for byte in (0..key.len() - 1).step_by(2) {
                key_bytes[i] = u8::from_str_radix(&key[byte..byte + 2], 16).unwrap();
                i += 1;
            }

            keys.insert(first_byte, Key::from(&key_bytes));
        }

        keys
    };

    /// Load the RSA private key into memory.
    static ref RSA_PRIVATE_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs1_pem(RSA_KEY).unwrap();
}

pub trait PacketSender {
    /// Invoked when a packet should be sent.
    fn send(&self, data: GamePacket);
}

/// Runs the actual packet sniffer.
pub fn run(
    config: Config,
    hook: Receiver<()>,
    tx: impl PacketSender + 'static
) -> Result<()> {
    // Create game packet processor.
    let mut processor = Processor::new(&config, tx);

    // Resolve the device by name.
    let device = if let Some(name) = &config.device_name {
        Device::list()?.into_iter().find(|d| d.name.eq(name))
    } else {
        Device::list()?.first().cloned()
    };

    // Check if the device was found.
    let device = match device {
        Some(device) => device,
        None => {
            return Err(anyhow!("No device (specified or unspecified) found."))
        }
    };

    trace!(
        "Using device {} ({}) for capturing.",
        match device.desc {
            Some(ref desc) => desc,
            None => "No description"
        },
        device.name
    );

    // Initialize the capture device.
    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .timeout(1)
        .open()?;

    // Apply a filter to the capture device.
    if let Some(filter) = &config.filter {
        trace!("Using capture filter: '{}'", filter);
        _ = capture.filter(filter.as_str(), true);
    }

    // Determine if the data link is Ethernet.
    let link = capture.get_datalink();
    let is_ethernet = link.eq(&Linktype::ETHERNET);

    // Run capture loop.
    while hook.try_recv().is_err() {
        if let Ok(packet) = capture.next_packet() {
            parse_packet(&config, &mut processor, packet, is_ethernet);
        }
    }

    Ok(())
}

/// Packet parsing function from raw packet data.
fn parse_packet(
    config: &Config,
    processor: &mut Processor,
    packet: Packet,
    is_ethernet: bool
) {
    // Extract data from the packet.
    let (data, port) = {
        // Convert the packet data to a vector.
        let data = packet.data.to_vec();
        // Strip the ethernet header.
        let data = if is_ethernet { (&data[14..]).to_vec() } else { data };

        // Extract the port from the packet.
        let port = u16::from_be_bytes([data[20], data[21]]);
        // Strip the IPv4 header.
        let data = &data[20 + 8..];

        (Vec::from(data), port)
    };

    // Check the packet's source.
    let source = PacketSource::from(config, port);
    trace!("Received packet of length {} from {:?} ({}).", data.len(), source, port);

    // Pre-process the packet.
    if data.len() == 20 {
        // This is a handshake packet; we should probably interpret it.
        let opcode = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match opcode {
            CONNECT_CMD => {
                trace!("Connect handshake operation received from {:?}.", source);
            },
            CONV_CMD => {
                let conv = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let token = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

                processor.initialize(conv, token);

                trace!("Received conversation ID from server: ({}, {})", conv, token);
            },
            DISCONNECT_CMD => {
                trace!("Disconnect handshake operation received from {:?}.", source);
            },
            _ => warn!("Unknown handshake operation received: {:x?}", opcode)
        }
    } else {
        // This is a game packet; forward it to the processor.
        processor.receive(&data, source);
    }
}

/// Utility function to create a new KCP instance.
///
/// `conv`: The KCP conversation ID. \
/// `token`: The KCP token.
fn new_kcp(conv: u32, token: u32) -> Kcp<Writer> {
    let mut kcp = Kcp::new(conv, token, Writer);
    kcp.set_nodelay(true, 10, 2, false);
    kcp.set_wndsize(256, 256);

    kcp
}

/// Validates the packet data.
///
/// This works by checking for the magic bytes at the start and end of the packet.
///
/// # Packet Structure
///
/// |  Magic  |  CmdId  | Header Length | Data Length |   Header Bytes   |    Data Bytes    |  Magic  |
/// |---------|---------|---------------|-------------|------------------|------------------|---------|
/// | 2 bytes | 2 bytes | 2 bytes       | 4 bytes     | size = 3rd field | size = 4th field | 2 bytes |
fn is_valid(data: &[u8]) -> bool {
    if data.len() <= 2 {
        data[0] == 0x45 && data[1] == 0x67
    } else {
        data[0] == 0x45
            && data[1] == 0x67

            && data[data.len() - 2] == 0x89
            && data[data.len() - 1] == 0xAB
    }
}

/// Represents a 4096-bit encryption key.
#[derive(Clone)]
struct Key(Vec<u8>);

impl Key {
    /// Creates a new instance of the `Key`.
    pub fn new(seed: u64) -> Self {
        let mut generator = MT19937_64::default();
        generator.seed(seed);

        let seed = generator.next_ulong();
        generator.seed(seed);

        let _ = generator.next_ulong(); // Skip the first number.

        // Generate the key.
        let mut bytes = vec![];
        for _ in (0..4096).step_by(8) {
            bytes.put_u64(generator.next_ulong());
        }

        Key(bytes)
    }

    /// Creates a new instance of the `Key`.
    /// Uses an existing key.
    pub fn from(key: &[u8]) -> Self {
        Key(key.to_vec())
    }

    /// Performs an XOR cipher on the data.
    /// data: The data to encrypt/decrypt.
    pub fn xor(&self, data: &mut [u8]) {
        cryptography::xor(data, &self.0);
    }

    /// Performs an XOR cipher on the data.
    ///
    /// If the data fails the `is_valid` check, it will throw an error.
    pub fn xor_or(&self, data: &mut [u8]) -> Result<()> {
        self.xor(data);

        match is_valid(data) {
            true => Ok(()),
            false => {
                self.xor(data);
                Err(anyhow!("Failed to decrypt data with existing key."))
            }
        }
    }

    /// Compares this key to the pre-computed values.
    /// known: The known prefix and suffix of the key.
    /// data: The test data to compare against.
    pub fn compare(&self, known: ([u8; 2], [u8; 2]), data: &[u8]) -> bool {
        let (prefix, suffix) = known;

        let data_len = data.len();
        let key_len = self.0.len();

        let prefix_valid = self.0[0] == prefix[0] && self.0[1] == prefix[1];
        let suffix_valid =
            self.0[(data_len - 2) % key_len] == suffix[0] &&
                self.0[(data_len - 1) % key_len] == suffix[1];

        prefix_valid && suffix_valid
    }
}

/// Represents the type of key in use during encryption.
enum PacketKey {
    None,

    /// The 'dispatch' key can be sourced from the API that handles region selection.
    ///
    /// In our case, we use a hardcoded list of them to prevent the need for an API.
    Dispatch(Key),

    /// The session key is derived from a seed.
    /// The seed itself is a secret that is derived from a client and server seed.
    ///
    /// See the 'Diffie–Hellman key exchange' for a similar concept.
    Session(Key)
}

/// UDP packet processor for the game.
///
/// Packets inputted are decoded with the KCP protocol.
/// The remaining traffic is decrypted using a brute-force technique.
///
/// # Example
///
/// ```rust,no_run
/// use ys_sniffer::{Config, PacketSource, Processor};
///
/// let config = Config::default();
/// let (tx, rx) = crossbeam_channel::unbounded();
/// let mut processor = Processor::new(&config, tx);
///
/// // Initialize & add data.
/// processor.initialize(0, 0);
/// processor.receive(&[0x00], PacketSource::Client);
///
/// // Listen for packets.
/// let packet = rx.recv().unwrap();
/// ```
pub struct Processor {
    packet_consumer: Box<dyn PacketSender>,
    known_seeds: &'static Path,

    key: PacketKey,
    handshake: Option<(u64, u64)>,

    client: Kcp<Writer>,
    server: Kcp<Writer>
}

impl Processor {
    /// Creates a new instance of the `Processor`.
    pub fn new(config: &Config, tx: impl PacketSender + 'static) -> Self {
        let seeds_path = config.known_seeds.clone();
        let seeds_path = Box::leak(seeds_path.into_boxed_str());

        Processor {
            packet_consumer: Box::new(tx),
            known_seeds: Path::new(seeds_path),
            key: PacketKey::None,
            handshake: None,
            client: Kcp::default(),
            server: Kcp::default()
        }
    }

    /// (re-)Initializes the processor.
    pub fn initialize(&mut self, conv: u32, token: u32) {
        self.client = new_kcp(conv, token);
        self.server = new_kcp(conv, token);
    }

    /// Event handler for when a packet is received.
    pub fn receive(&mut self, data: &[u8], side: PacketSource) {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32;

        if side.is_client() {
            _ = self.client.update(time);
            _ = self.client.input(data);
        } else {
            _ = self.server.update(time);
            _ = self.server.input(data);
        }

        // Process packets for both sides.
        self.process(PacketSource::Client);
        self.process(PacketSource::Server);
    }

    /// Processes a packet.
    fn process(&mut self, side: PacketSource) {
        let kcp = if side.is_client() { &mut self.client } else { &mut self.server };

        // Check if any data is available.
        let size = match kcp.peeksize() {
            Ok(size) => size,
            Err(_) => return
        };

        // Allocate a buffer for the data.
        let mut buffer = vec![0; size];
        match kcp.recv(&mut buffer) {
            Ok(_) => {
                if let Ok(packet) = self.decode_packet(buffer, side) {
                    // Pass the packet to the preprocessor briefly.
                    self.preprocess(&packet);

                    _ = self.packet_consumer.send(packet);
                }
            },
            Err(_) => {}
        }
    }

    /// This method is used to check if the packet is an encryption handshake packet.
    ///
    /// If it is, we store its data for use in the future.
    fn preprocess(&mut self, packet: &GamePacket) {
        // Check if the encryption key has been found.
        if self.handshake.is_some() {
            return;
        }

        // Decode the packet's data.
        let data = match protoshark::decode(&packet.data) {
            Ok(data) => data,
            Err(error) => {
                println!("{}", BASE64_STANDARD.encode(&packet.data));
                warn!("Failed to decode packet data: {}", error);
                return;
            }
        };

        // Search for `bytes` fields.
        for (_, value) in data {
            match value {
                Value::String(string) => {
                    // Check if the string is valid Base64.
                    let Ok(bytes) = BASE64_STANDARD.decode(&string) else {
                        continue;
                    };

                    // Try to RSA-decrypt the data.
                    let Ok(decrypted) = RSA_PRIVATE_KEY.decrypt(Pkcs1v15Encrypt, &bytes) else {
                        continue;
                    };

                    // In the case that both of these succeed, we can assume this is the handshake packet.
                    // First, we need to determine when the packet was sent.
                    let Ok(header) = protoshark::decode(&packet.header) else {
                        error!("Failed to decode packet header: invalid format");
                        return;
                    };

                    // Get the `sent_ms` field.
                    // This is always field 6 if decoded properly.
                    let Some(Value::VarInt(sent_time)) = header.get(&6) else {
                        error!("Failed to decode packet header: `sent_ms` field not found");
                        return;
                    };
                    let Some(sent_time) = sent_time.as_u64() else {
                        error!("Failed to decode packet header: `sent_ms` field not a u64");
                        return;
                    };

                    // Parse the server seed from binary.
                    let server_seed = u64::from_be_bytes(decrypted[0..8].try_into().unwrap());

                    // Store the handshake data.
                    self.handshake = Some((sent_time, server_seed));
                },
                _ => {}
            }
        }
    }

    /// Decrypts the packet.
    pub fn decode_packet(&mut self, data: Vec<u8>, side: PacketSource) -> Result<GamePacket> {
        let data = self.decrypt_packet(data)?;

        // Parse the packet.
        let id = u16::from_be_bytes([data[2], data[3]]);
        let header_size = u16::from_be_bytes([data[4], data[5]]) as usize;

        let header = data[10..10 + header_size].to_vec();
        let data = data[10 + header_size..data.len() - 2].to_vec();

        Ok(GamePacket {
            id,
            header,
            data,
            source: side
        })
    }

    /// Attempts to decrypt the packet.
    fn decrypt_packet(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>> {
        match self.key {
            PacketKey::None => {
                // No key has been picked yet; try using a dispatch key.
                let index = u16::from_be_bytes([data[0] ^ 0x45, data[1] ^ 0x67]);
                let key = match DISPATCH_KEYS.get(&index) {
                    Some(key) => key,
                    None => return Err(anyhow!("No key found for index: {}", index))
                };

                // Switch to the dispatch key.
                self.key = PacketKey::Dispatch(key.clone());

                // Decrypt the data.
                key.xor(&mut data);
                Ok(data)
            },
            PacketKey::Session(ref key) => {
                match key.xor_or(&mut data) {
                    Ok(_) => Ok(data),
                    Err(_) => {
                        warn!("Failed to decrypt data with existing key, session change?");

                        self.key = PacketKey::None;
                        self.decrypt_packet(data)
                    }
                }
            },
            PacketKey::Dispatch(ref key) => {
                // Try decrypting the packet.
                if let Ok(_) = key.xor_or(&mut data) {
                    return Ok(data);
                }

                // Attempt to brute-force the key.
                let (sent_time, seed) = match &self.handshake {
                    Some((sent_time, seed)) => (*sent_time, *seed),
                    None => return Err(anyhow!("No handshake data available.")),
                };

                match bruteforce(&self.known_seeds, sent_time, seed, &data) {
                    Some(seed) => {
                        // Create the session key.
                        let key = Key::new(seed);
                        self.key = PacketKey::Session(key.clone());

                        match key.xor_or(&mut data) {
                            Ok(_) => {
                                trace!("Encryption key found for session! Seed: {}", seed);
                                Ok(data)
                            },
                            Err(_) => {
                                warn!("Failed to decrypt data with new key, session change?");

                                self.key = PacketKey::None;
                                self.decrypt_packet(data)
                            }
                        }
                    },
                    None => Err(anyhow!("Unable to find the encryption key seed."))
                }
            }
        }
    }
}

/// Attempts to bruteforce the encryption key's seed.
fn bruteforce(
    seeds_file: &Path,
    sent_time: u64, server_seed: u64,
    data: &[u8]
) -> Option<u64> {
    // Load already known seeds from the disk.
    let mut file_content = "".to_string();
    if seeds_file.exists() {
        file_content = utils::read_file(seeds_file).unwrap();
        for line in file_content.lines() {
            let seed = line.parse().unwrap();
            if let Some(seed) = try_seed(seed, server_seed, 10000, data) {
                return Some(seed);
            }
        }

        // Trim any trailing whitespace.
        file_content = file_content.trim().to_string();
    }

    // Generate new seeds.
    for i in 0..3000i64 {
        let offset = if i % 2 == 0 { i / 2 } else { -(i - 1) / 2 };
        let time = sent_time as i64 + offset; // This will act as the seed.

        if let Some(key) = try_seed(time, server_seed, 5, data) {
            // If a seed is found, we should save it.
            // (we don't actually save the seed, rather we save the time which acts similarly to the seed)
            let content = match seeds_file.exists() {
                true => format!("{}\n{}", file_content, time),
                false => time.to_string()
            };
            utils::write_file(seeds_file, content).unwrap();

            return Some(key);
        }
    }

    None
}

/// Attempts to bruteforce the encryption key's seed.
fn try_seed(
    client_guess: i64,
    server_seed: u64,
    depth: i32,
    test: &[u8]
) -> Option<u64> {
    // Calculate the known prefix and suffix of the key.
    let prefix = [test[0] ^ 0x45, test[1] ^ 0x67];
    let suffix = [
        test[test.len() - 2] ^ 0x89,
        test[test.len() - 1] ^ 0xAB,
    ];

    // Attempt to generate the key.
    let mut generator = Random::seeded(client_guess as i32);
    for _ in 0..depth {
        let client_seed = generator.next_safe_uint64();

        let seed = client_seed ^ server_seed;
        let key = Key::new(seed);

        if key.compare((prefix, suffix), test) {
            return Some(seed);
        }
    }

    None
}

#[derive(Default)]
pub struct Writer;

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}