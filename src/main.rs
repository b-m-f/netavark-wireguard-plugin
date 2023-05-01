use netavark_wireguard_plugin::sockets::{join_netns, GenericSocket};

use ipnet::IpNet;
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};

use log::debug;

use netavark::{
    error::ErrorWrap,
    network::{core_utils::open_netlink_sockets, netlink, types},
    new_error,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};
use netlink::Route;
use netlink_packet_route::nlas::link::InfoKind;

use netlink_packet_wireguard::constants::{AF_INET, AF_INET6};
use netlink_packet_wireguard::nlas::{
    WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs,
};

use netlink::CreateLinkOptions;

fn main() {
    let info = Info::new("1.0.0".to_owned(), API_VERSION.to_owned(), None);

    PluginExec::new(Exec {}, info).exec();
}

#[derive(Debug)]
struct Peer {
    /// IPs that will be forwarded to the Peer
    /// and from which traffic is accepted
    allowed_ips: Vec<IpNet>,
    /// Seconds between Handshakes sent to peer
    /// in order to keep the connection alive
    /// Optional
    persistent_keepalive: Option<u16>,
    /// Peers public key to verify traffic during crypto routing
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
}

#[derive(Debug)]
struct WireGuard {
    /// WireGuard interface name
    interface_name: String,
    /// addresses of the WireGuard interface
    addresses: Vec<IpNet>,
    ///
    private_key: [u8; 32],
    /// mtu for the network interface (0 if default)
    mtu: u16,
    /// WireGuard peers
    peers: Vec<Peer>,
    /// Listening Port
    /// Optional
    port: Option<u16>,
}

struct Exec {}

impl Plugin for Exec {
    fn create(
        &self,
        network: types::Network,
    ) -> Result<types::Network, Box<dyn std::error::Error>> {
        match network.options.as_ref() {
            Some(options) => {
                if options.get("config") == None {
                    return Err(new_error!("no path to WireGuard config file provided"));
                }
            }
            None => return Err(new_error!("no path to WireGuard config file provided")),
        };

        Ok(network)
    }

    fn setup(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        let (mut host_sock, mut netns_sock) = open_netlink_sockets(&netns)?;

        // The existence of the config option was checked during the network creation
        // in the create function
        let options = opts.network.options.unwrap_or_default();
        let config = options.get("config").unwrap();
        // Interface names can have a lenght of maximum 15 chars.
        // The name is is chosen from the network name, as this holds the WireGuard config
        let interface_name: String = ("wg-".to_owned() + &opts.network.name)
            .chars()
            .into_iter()
            .take(15)
            .collect();
        let data = match parse_config(config, interface_name.clone()) {
            Ok(data) => data,
            Err(e) => return Err(new_error!("{}", e)),
        };

        // Peer Validation
        for (index, peer) in data.peers.iter().enumerate() {
            if peer.public_key == [0; 32] {
                return Err(new_error!(
                    "invalid WireGuard configuration: Peer #{:?} is missing a PublicKey",
                    index
                ));
            }
            if peer.allowed_ips.is_empty() {
                return Err(new_error!(
                    "invalid WireGuard configuration: Peer #{:?} is missing AllowedIPs",
                    index
                ));
            }
        }

        // Interface Validation
        // will succeed if the interface has an Address and a PrivateKey
        if data.private_key == [0; 32] {
            return Err(new_error!(
                "invalid WireGuard configuration: Interface is missing a PrivateKey"
            ));
        }
        if data.addresses.is_empty() {
            return Err(new_error!(
                "invalid WireGuard configuration: Interface is missing an Address"
            ));
        }

        debug!("Setup network {}", opts.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            interface_name, data.addresses
        );
        match create_wireguard_interface(
            &mut host_sock.netlink,
            &mut netns_sock.netlink,
            &data,
            host_sock.fd,
            netns_sock.fd,
        ) {
            Ok(interface) => interface,
            Err(e) => return Err(new_error!("{}", e)),
        };

        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();
        interfaces.insert(
            interface_name,
            types::NetInterface {
                mac_address: "".to_string(),
                subnets: None,
            },
        );

        let response = types::StatusBlock {
            dns_server_ips: None,
            dns_search_domains: None,
            interfaces: Some(interfaces),
        };

        Ok(response)
    }

    fn teardown(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_, mut netns) = open_netlink_sockets(&netns)?;
        let interface_name: String = ("wg-".to_owned() + &opts.network.name)
            .chars()
            .into_iter()
            .take(15)
            .collect();
        netns
            .netlink
            .del_link(netlink::LinkID::Name(interface_name))?;

        Ok(())
    }
}

fn create_wireguard_interface(
    host: &mut netlink::Socket,
    netns_link_socket: &mut netlink::Socket,
    data: &WireGuard,
    hostns_fd: i32,
    netns_fd: i32,
) -> Result<String, String> {
    match join_netns(netns_fd) {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Error when trying to join network namespace: {}",
                e
            ))
        }
    };
    let mut netns_generic_socket = match GenericSocket::new() {
        Ok(socket) => socket,
        Err(e) => return Err(format!("Error when creating generic netlink socket: {}", e)),
    };

    match join_netns(hostns_fd) {
        Ok(_) => (),
        Err(e) => return Err(format!("Error when trying to join host namespace: {}", e)),
    };

    let mut create_link_opts =
        CreateLinkOptions::new(data.interface_name.to_string(), InfoKind::Wireguard);
    create_link_opts.mtu = data.mtu as u32;

    debug!(
        "Creating WireGuard interface {}",
        data.interface_name.to_string()
    );

    match host.create_link(create_link_opts) {
        Ok(_) => (),
        Err(e) => return Err(format!("Error when creating WireGuard interface: {}", e)),
    }

    let link = host
        .get_link(netlink::LinkID::Name(data.interface_name.to_string()))
        .wrap("get WireGuard interface")
        .unwrap();

    debug!(
        "Moving WireGuard interface {} from namespace {} to container namespace {}",
        data.interface_name.to_string(),
        hostns_fd,
        netns_fd
    );
    match host.set_link_ns(link.header.index, netns_fd) {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Error when moving WireGuard interface to container network namespace: {}",
                e
            ))
        }
    }

    debug!(
        "Adding Addresses to WireGuard interface {}",
        data.interface_name.to_string()
    );

    for addr in &data.addresses {
        match netns_link_socket.add_addr(link.header.index, addr) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "Error setting address of WireGuard interface: {}",
                    e
                ))
            }
        }
    }

    let nlas = generate_wireguard_device_nlas(data);

    debug!(
        "Setting up WireGuard interface {}",
        data.interface_name.to_string()
    );

    match netns_generic_socket.set_wireguard_device(nlas) {
        Ok(_) => (),
        Err(e) => return Err(format!("Error adding WireGuard interface settings: {}", e)),
    }

    if !data.peers.is_empty() {
        debug!(
            "Adding Peers to WireGuard interface {}",
            data.interface_name.to_string()
        );

        for peer in data.peers[..].iter() {
            let nlas = generate_peer_nlas_for_wireguard_device(peer, data.interface_name.clone());
            match netns_generic_socket.set_wireguard_device(nlas) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!(
                        "Error adding Peer {:?} to WireGuard interface: {}",
                        peer, e
                    ))
                }
            }
        }
    }

    debug!(
        "Activating WireGuard interface {}",
        data.interface_name.to_string(),
    );

    match netns_link_socket.set_up(netlink::LinkID::Name(data.interface_name.to_string())) {
        Ok(_) => (),
        Err(e) => return Err(format!("Error when setting WireGuard interface up: {}", e)),
    }

    for peer in data.peers.iter() {
        let routes = generate_routes_for_peer(&data.addresses, &peer.allowed_ips);
        for route in routes {
            match netns_link_socket.add_route(&route) {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!(
                        "Error when adding route {} for WireGuard peer: {}",
                        &route, e
                    ))
                }
            };
        }
    }

    Ok(data.interface_name.clone())
}
//
fn parse_config(path: &String, interface_name: String) -> Result<WireGuard, String> {
    // Get configuration data from file
    let config_data = match std::fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) => return Err(format!("problem reading WireGuard config: {:?}", e)),
    };

    // Setup line based parsing
    // with empty data structures to store into
    //
    // Only Peer and Interface sections exists
    // [Interface] can only be specified once and subsequent definitions
    // will overwrite previously stored data
    //
    // If a [Peer] section is encountered a new Peer is added
    let lines = config_data.lines();
    let mut peers: Vec<Peer> = vec![];
    let mut interface = WireGuard {
        interface_name: "".to_string(),
        addresses: vec![],
        private_key: [0x00; 32],
        mtu: 1420,
        peers: vec![],
        port: None,
    };
    let mut interface_section = false;
    let mut peer_section = false;

    for (index, line) in lines.into_iter().enumerate() {
        if line.trim_start() == "" || line.trim_start().chars().next().unwrap().to_string() == "#" {
            continue;
        }
        if line == "[Interface]" {
            interface_section = true;
            peer_section = false;
            continue;
        }
        if line == "[Peer]" {
            interface_section = false;
            peer_section = true;
            // Add a new peer to the peers array
            // which will be used to store information
            // from lines that will be parsed next
            peers.push(Peer {
                allowed_ips: vec![],
                persistent_keepalive: None,
                public_key: [0; 32],
                preshared_key: None,
                endpoint: None,
            });
            continue;
        }
        // splitting once gives key and value.
        // Using any other split can conflict with the base64 encoded keys
        let (key, value) = match line.split_once('=') {
            Some(tuple) => {
                let key: String = tuple.0.split_whitespace().collect();
                let value: String = tuple.1.split_whitespace().collect();
                (key, value)
            }
            None => {
                return Err(format!(
                    "when parsing WireGuard configuration {} on line: {}.",
                    line, index
                ))
            }
        };
        if !key.is_empty() && value.is_empty() && value.is_empty() {
            return Err(format!(
                "when parsing WireGuard configuration {} on line {}.  No value provided.",
                key, index
            ));
        }
        if interface_section {
            match key.as_str() {
                "Address" => {
                    let ip_with_cidr = add_cidr_to_ip_addr_if_missing(value.clone());
                    let ip: IpNet = match ip_with_cidr.parse() {
                        Ok(ip) => ip,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard interface address: {:?}",
                                e, value
                            ))
                        }
                    };
                    interface.addresses.push(ip)
                }
                "ListenPort" => {
                    let port = match value.parse::<u16>() {
                        Ok(port) => port,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard interface port: {:?}",
                                e, value
                            ));
                        }
                    };
                    interface.port = Some(port);
                }
                "PrivateKey" => {
                    interface.private_key = match base64.decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => key,
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PrivateKey: {:?}. Is it 32 bytes?",
                                    e, value
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PrivateKey: {:?}",
                                e, value
                            ))
                        }
                    }
                }
                _ => {
                    debug!(
                        "Ignoring key `{}` in WireGuard interface configuration",
                        key
                    );
                }
            }
        }
        if peer_section {
            let current_peer_index = peers.len() - 1;
            let current_peer = &mut peers[current_peer_index];
            match key.as_str() {
                "AllowedIPs" => {
                    let ips = value.split(',');
                    for ip in ips {
                        let ip_with_cidr = add_cidr_to_ip_addr_if_missing(ip.to_string());
                        let ip: IpNet = match ip_with_cidr.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                    return Err(format!(
                                        "{:?} when parsing WireGuard peers AllowedIPs: {:?}. Occurs in {:?}",
                                        e, value, ip
                                    ))
                            }
                        };
                        current_peer.allowed_ips.push(ip);
                    }
                }
                "Endpoint" => {
                    current_peer.endpoint = match parse_endpoint(value.clone()) {
                        Ok(endpoint) => endpoint,
                        Err(e) => {
                            return Err(format!(
                                "when trying to parse Endpoint {} for peer {}: {:?}",
                                value, current_peer_index, e
                            ))
                        }
                    }
                }
                "PublicKey" => {
                    current_peer.public_key = match base64.decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => key,
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PublicKey: {:?} for peer {:?}. Is it 32 bytes?",
                                    e, value, current_peer_index
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PublicKey: {:?} for peer {:?}",
                            e, value, current_peer_index
                            ))
                        }
                    }
                }
                "PresharedKey" => {
                    current_peer.preshared_key = match base64.decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => Some(key),
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PresharedKey: {:?} for peer {:?}. Is it 32 bytes?",
                                    e, value, current_peer_index
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PresharedKey: {:?} for peer {:?}",
                            e, value, current_peer_index
                            ))
                        }
                    }
                }
                "PersistentKeepalive" => {
                    let keepalive = match value.parse::<u16>() {
                        Ok(keepalive) => keepalive,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard peers PersistentKeepalive value: {:?}",
                                e, value
                            ));
                        }
                    };
                    current_peer.persistent_keepalive = Some(keepalive);
                }
                _ => {
                    debug!("Ignoring key `{}` in WireGuard peer configuration", key);
                }
            }
        }
    }

    interface.interface_name = interface_name;
    interface.peers = peers;

    Ok(interface)
}

fn add_cidr_to_ip_addr_if_missing(addr: String) -> String {
    let mut ip4_cidr = "/32".to_string();
    let mut ip6_cidr = "/128".to_string();
    match addr.split_once('/') {
        Some(_) => addr, // CIDR was defined, nothing to do
        None => {
            // default to a host CIDR
            if addr.contains(':') {
                ip6_cidr.insert_str(0, &addr);

                ip6_cidr
            } else {
                ip4_cidr.insert_str(0, &addr);

                ip4_cidr
            }
        }
    }
}

fn parse_endpoint(addr: String) -> Result<Option<SocketAddr>, String> {
    let (endpoint_addr, endpoint_port) = match addr.split_once(':') {
        Some(tuple) => tuple,
        None => return Err("incomplete Endpoint address".to_string()),
    };
    let port: u16 = match endpoint_port.parse() {
        Ok(ip) => ip,
        Err(e) => return Err(format!("incorrect port: {}", e)),
    };

    let ip: IpAddr = match endpoint_addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            // we might have gotten a hostname in the config
            // try this next
            match addr.to_socket_addrs() {
                Ok(mut addr) => match addr.next() {
                    Some(addr) => addr.ip(),
                    None => {
                        return Err(format!("could not parse {:?}", addr));
                    }
                },
                Err(_) => {
                    return Err(format!("could not parse {:?}", addr));
                }
            }
        }
    };

    Ok(Some(SocketAddr::new(ip, port)))
}
//
fn generate_wireguard_device_nlas(data: &WireGuard) -> Vec<WgDeviceAttrs> {
    let mut nlas = vec![
        WgDeviceAttrs::IfName(data.interface_name.to_string()),
        WgDeviceAttrs::PrivateKey(data.private_key),
    ];

    if let Some(port) = data.port {
        nlas.push(WgDeviceAttrs::ListenPort(port))
    }
    nlas
}

// This has to be allowed since Clippy's suggestion seems
// off
// 609 ~     let mut wg_peer = WgPeer(<[_]>::into_vec(
// 610 +             #[rustc_box]
// 611 +             $crate::boxed::Box::new([$($x),+])
// 612 ~         ));

#[allow(clippy::init_numbered_fields)]
fn generate_peer_nlas_for_wireguard_device(
    peer: &Peer,
    interface_name: String,
) -> Vec<WgDeviceAttrs> {
    let mut allowed_ip_nla = vec![];
    for ip in peer.allowed_ips[..].iter() {
        let mut family: u16 = AF_INET;

        match ip {
            IpNet::V4(_) => (),
            IpNet::V6(_) => family = AF_INET6,
        }
        allowed_ip_nla.push(WgAllowedIp {
            0: vec![
                WgAllowedIpAttrs::IpAddr(ip.network()),
                WgAllowedIpAttrs::Cidr(ip.prefix_len()),
                WgAllowedIpAttrs::Family(family),
            ],
        });
    }
    let mut wg_peer = WgPeer {
        0: vec![
            WgPeerAttrs::PublicKey(peer.public_key),
            WgPeerAttrs::AllowedIps(allowed_ip_nla),
        ],
    };
    if let Some(key) = peer.preshared_key {
        wg_peer.0.push(WgPeerAttrs::PresharedKey(key))
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        wg_peer.0.push(WgPeerAttrs::PersistentKeepalive(keepalive))
    }
    if let Some(endpoint) = peer.endpoint {
        wg_peer.0.push(WgPeerAttrs::Endpoint(endpoint))
    }
    let nlas = vec![
        WgDeviceAttrs::IfName(interface_name),
        WgDeviceAttrs::Peers(vec![wg_peer]),
    ];
    nlas
}

fn generate_routes_for_peer(interface_addresses: &[IpNet], allowed_ips: &[IpNet]) -> Vec<Route> {
    let mut routes = vec![];
    for gateway in interface_addresses {
        match gateway {
            IpNet::V4(gateway) => {
                for dest in allowed_ips {
                    match dest {
                        IpNet::V4(dest) => {
                            let route: Route = Route::Ipv4 {
                                dest: *dest,
                                gw: gateway.addr(),
                                metric: None,
                            };
                            routes.push(route);
                        }
                        IpNet::V6(_) => {
                            continue;
                        }
                    }
                }
            }
            IpNet::V6(gateway) => {
                for dest in allowed_ips {
                    match dest {
                        IpNet::V4(_) => {
                            continue;
                        }
                        IpNet::V6(dest) => {
                            let route: Route = Route::Ipv6 {
                                dest: *dest,
                                gw: gateway.addr(),
                                metric: None,
                            };
                            routes.push(route);
                        }
                    }
                }
            }
        }
    }
    routes
}
