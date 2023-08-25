// Prelude packages.
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::mpsc::channel;
use std::time::Duration;
use threadpool::ThreadPool;

// Subnet IP Ping sweep for hosts. Returns an IpAddr vector of results.
pub fn ip_scan(subnet: &String) -> Vec<IpAddr> {
    // Set ping scan settings.
    let timeout: Option<Duration> = Some(Duration::from_millis(128));
    let ttl: Option<u32> = Some(64);
    let ident: Option<u16> = None;
    let seq_cnt: Option<u16> = Some(1);
    let payload = None;

    // Create a channel to receive the results.
    let (tx, rx) = channel();

    // Define host range and format address for scanner.
    for ip in 1..255 {
        let address: IpAddr = format!("{}{}", subnet, ip).trim().parse().unwrap();

        // Test each address with ping.
        match ping::ping(address, timeout, ttl, ident, seq_cnt, payload) {
            Ok(_) => {
                // Send scan results to channel.
                tx.send(address).unwrap();
            }
            Err(_) => {}
        };
    }

    // Close the channel so that the receiver can finish its work.
    drop(tx);

    // Return results as vector.
    return rx.into_iter().collect::<Vec<IpAddr>>();
}

// Scan a single IP address for open ports. Returns u32 vector of results.
pub fn port_scan(target_ip: &String, start_port: u32, end_port: u32, threads: usize) -> Vec<u32> {
    // Set timeout (ms) and threads per CPU core.
    const TIMEOUT_MILLIS: u64 = 256;

    // Create thread pool
    let pool = ThreadPool::new(threads);

    // Create a channel to send results.
    let (tx, rx) = channel();

    // Format target address.
    let target_ip: Ipv4Addr = target_ip.trim().parse().unwrap();

    // Format full address with port number.
    for port in start_port..=end_port {
        let address = format!("{}:{}", target_ip, port).parse().unwrap();

        // Clone the sender
        let tx = tx.clone();
        pool.execute(move || {
            match TcpStream::connect_timeout(&address, Duration::from_millis(TIMEOUT_MILLIS)) {
                Ok(_) => {
                    // Send the open port number to the main thread.
                    tx.send(port).unwrap();
                }
                Err(_) => {}
            }
        });
    }

    // Close the channel so that the receiver can finish its work.
    drop(tx);

    // Retrieve ports from scan, create vector.
    return rx.into_iter().collect::<Vec<u32>>();
}

// Maps port numbers from a hashmap of port names imported from txt file.
pub fn port_map(portnum: u32) {

    // Read txt file from txt file.
    let file = File::open("./ports.txt").expect("Failed to open file, make sure ports.txt is in root directory");
    let reader = BufReader::new(file);

    // Create hashmap.
    let mut hashmap: HashMap<u32, String> = HashMap::new();

    // Read lines from txt file.
    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split("=").collect();

        // Separate lines by "=" symbol. Insert results to hashmap.
        if parts.len() == 2 {
            let key = parts[0].parse::<u32>().expect("Failed to parse key");
            let value = parts[1].to_string();
            hashmap.insert(key, value);
        }
    }

    // Print results.
    print!("  {}", portnum);
    if let Some(name) = hashmap.get(&portnum) {
        print!("  {}", name);
    };
    println!();
}
