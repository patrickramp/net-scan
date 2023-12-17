// Prelude, load libraries.
use netlib::*;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

const SPLASH: &str = "
  ███╗   ██╗███████╗████████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║ █████╗ ███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║ ╚════╝ ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║        ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ v7.21.2023
Multi-function high-speed network scanner written in Rust. -By Securitops";

pub const MENU: &str = "
    Main Menu:
        [1] Ping-sweep IPv4 subnet for devices.
        [2] Scan IPv4 address for open ports.
        [3] Scan subnet for specific open ports.
        [4] Exit program.\n";

pub const BREAK: &str = "
===============================================================";

// Entry point.
fn main() {
    println!("{}", SPLASH);
    loop {
        println!("{}", MENU);
        pick();
    }
}

// Menu Picker.
pub fn pick() {
    let mut option = String::new();
    io::stdin().read_line(&mut option).unwrap();
    match option.trim().parse::<u8>() {
        Ok(1) => {
            // Ping-sweep IPv4 subnet for devices.
            subnet_scanner();
        }
        Ok(2) => {
            // Scan IPv4 address for open ports.
            port_scanner();
        }
        Ok(3) => {
            // Scan IPv4 address for open ports.
            spec_scanner();
        }
        Ok(4) => {
            println!("Thank you for using Net-Scan! Goodbye.");
            std::process::exit(0);
        }
        Ok(42) => {
            println!(
                "CONGRATULATIONS, You have found the answer to the the greatest question in the universe.
The answer to the meaning of life, the universe, and everything!.. But what was the question?"
            );
            pick();
        }
        Ok(69) => {
            println!("69... Nice!");
            pick();
        }
        Ok(_) => {
            println!("Not an option, try again.");
            pick();
        }
        Err(_) => {
            println!("ERROR: Invalid option, try again.");
            pick();
        }
    }
}

// Use ping-sweep to detect hosts on subnet.
fn subnet_scanner() {
    // Get target subnet from user.
    println!("Enter network address: (ie. 192.168.1.  )");
    let mut subnet = String::new();
    io::stdin().read_line(&mut subnet).unwrap();
    let mut subnet = subnet.trim().to_string();

    // Check for valid IpAddr network address.
    let check = format!("{}254", subnet).trim().parse::<IpAddr>();
    match check {
        Ok(_) => {
            println!(
                "
===============================================================
    Scanning subnet {}*** for hosts. Please wait...
===============================================================",
                subnet,
            );

            // Start scan timer.
            let start_time = Instant::now();

            // Collect Vec. of network devices from ip_scan..
            let mut open_hosts: Vec<IpAddr> = ip_scan(&mut subnet);
            open_hosts.sort_unstable();

            // Stop timer.
            let duration = start_time.elapsed();

            // Return scan results.
            if open_hosts.is_empty() {
                println!(
                    "Scan took {} seconds and found no open hosts.",
                    duration.as_secs()
                );
            } else {
                println!(
                    "Scan took {} seconds and found {} open hosts:",
                    duration.as_secs(),
                    open_hosts.len()
                );
                for open_ip in open_hosts.iter() {
                    println!("  {}", open_ip);
                }
            }
            println!("{}", BREAK);
        }
        Err(_) => {
            println!(
                "
ERROR: Cannot parse subnet (Please check formatting and try again!)\n"
            );
            subnet_scanner();
        }
    };
}

// Scan for open ports.
fn port_scanner() {
    // Get target IP address from user.
    println!("Enter IPv4 address to scan: (ie. 192.168.1.1)");
    let mut target_ip = String::new();
    io::stdin().read_line(&mut target_ip).unwrap();

    // Check for a valid IPv4 address.
    let check = (target_ip).trim().parse::<Ipv4Addr>();
    match check {
        Ok(_) => {
            // Get range of ports to scan from user.
            let mut start_port = String::new();
            let mut end_port = String::new();
            println!("Enter lowest port number to scan:");
            io::stdin().read_line(&mut start_port).unwrap();
            println!("Enter highest port to scan (Limit 65535):");
            io::stdin().read_line(&mut end_port).unwrap();
            let start_port: u32 = start_port.trim().parse().unwrap();
            let end_port: u32 = end_port.trim().parse().unwrap();

            // Check port range is valid.
            if end_port > 65535 {
                println!("ERROR: Not a valid port number! Must be less than 65535!\n");
                port_scanner();
            } else if start_port > end_port {
                println!("ERROR: Lowest port must smaller than highest port!\n");
                port_scanner();
            } else {
                // Set number of threads and determine number of ports scanned.
                let threads: usize = 4 * num_cpus::get();
                let n_ports: u32 = end_port - start_port + 1;
                println!(
                    "
===============================================================
    Scanning {} ports with {} threads. Please wait...
===============================================================",
                    n_ports, threads
                );

                // Start scan timer.
                let start_time = Instant::now();

                // Collect Vec. of open ports.
                let mut open_ports: Vec<u32> =
                    port_scan(&mut target_ip, start_port, end_port, threads);
                open_ports.sort_unstable();

                // Stop timer.
                let duration = start_time.elapsed();

                // Print scan results
                println!(
                    "Scan of ports {}-{} on host {}",
                    start_port, end_port, target_ip,
                );
                println!(
                    "took {} seconds and found {} open ports:",
                    duration.as_secs(),
                    open_ports.len()
                );
                // Identify ports.
                for port in open_ports {
                    port_map(port);
                }
            }
            println!("{}", BREAK);
        }
        Err(_) => {
            println!(
                "
ERROR: Unable to parse address.
Please check formatting and try again!\n"
            );
            port_scanner();
        }
    };
}

// Scan range of open ports on specific subnet.
fn spec_scanner() {

    // Get target subnet from user.
    println!("Enter network address: (ie. 192.168.1.  )");
    let mut subnet = String::new();
    io::stdin().read_line(&mut subnet).unwrap();
    let mut subnet = subnet.trim().to_string();

    // Check for valid network address.
    let check = format!("{}254", subnet).trim().parse::<IpAddr>();
    match check {
        Ok(_) => {
            // Get range of ports to scan from user.
            let mut start_port = String::new();
            let mut end_port = String::new();
            println!("Enter lowest port number to scan:");
            io::stdin().read_line(&mut start_port).unwrap();
            println!("Enter highest port to scan (Limit 65535):");
            io::stdin().read_line(&mut end_port).unwrap();
            let start_port: u32 = start_port.trim().parse().unwrap();
            let end_port: u32 = end_port.trim().parse().unwrap();

            // Check port range is valid.
            if end_port > 65535 {
                println!("ERROR: Not a valid port number! Must be less than 65535!\n");
                spec_scanner();
            } else if start_port > end_port {
                println!("ERROR: Lowest port must smaller than highest port!\n");
                spec_scanner();
            } else {
                // Set number of threads for scan, default is 8 per core.
                let threads: usize = 8 * num_cpus::get();
                // Determine number of ports scanned.
                let n_ports: u32 = end_port - start_port + 1;
                println!(
                    "
===============================================================
    Scanning {} ports on subnet {}*** Please wait...
===============================================================",
                    n_ports, subnet
                );

                // Start timer.
                let start_time = Instant::now();

                // Collect open hosts to scan.
                for target_ip in ip_scan(&mut subnet) {
                    let target_ip = target_ip.to_string();

                    // Scan found hosts for open ports.
                    let spec_ports = port_scan(&target_ip, start_port, end_port, threads);

                    // Return scan results.
                    if spec_ports.is_empty() {
                        println!("No open ports found on host {}", target_ip);
                    } else {
                        println!(
                            "Found {} open ports on host {}",
                            spec_ports.len(),
                            target_ip
                        );
                        for port in spec_ports {
                            port_map(port);
                        }
                        println!("{}", BREAK);
                    };
                }

                // Stop timer.
                let duration = start_time.elapsed();
                println!("Scan took {} seconds.", duration.as_secs());
            }
        }
        Err(_) => {
            println!(
                "
ERROR: Cannot parse subnet for:{}
(Please check formatting and try again!)\n",
                subnet
            );
            spec_scanner();
        }
    };
}
