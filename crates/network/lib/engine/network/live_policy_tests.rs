//! A running sandbox's network policy, changed live through the real network engine.

use std::net::Ipv4Addr;
use std::time::Duration;

use msb_krun::backends::net::{NetBackend, ReadError};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::io::AsyncWriteExt;

use super::{HostRoutes, SmoltcpNetwork};
use crate::config::{EnvNetworkSecretResolver, NetworkConfig};
use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct GuestDevice(Box<dyn NetBackend + Send>);

struct GuestRx(Vec<u8>);

struct GuestTx<'a>(&'a mut GuestDevice);

/// The guest side of a sandbox's network: its own TCP/IP stack on the virtio-net backend.
struct Guest {
    device: GuestDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    gateway: Ipv4Addr,
    started: std::time::Instant,
    next_port: u16,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Device for GuestDevice {
    type RxToken<'a> = GuestRx;
    type TxToken<'a> = GuestTx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(GuestRx, GuestTx<'_>)> {
        let mut frame = vec![0; 2048];
        match self.0.read_frame(&mut frame) {
            Ok(len) => Some((GuestRx(frame[12..len].to_vec()), GuestTx(self))),
            Err(ReadError::NothingRead) => None,
            Err(error) => panic!("reading guest frame: {error:?}"),
        }
    }

    fn transmit(&mut self, _: Instant) -> Option<GuestTx<'_>> {
        Some(GuestTx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1514;
        capabilities
    }
}

impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; 12 + len];
        let result = f(&mut frame[12..]);
        self.0.0.write_frame(12, &mut frame).unwrap();
        result
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Guest {
    fn attach(network: &mut SmoltcpNetwork) -> Self {
        let bootstrap = network.guest_bootstrap_network();
        let ipv4 = bootstrap.ipv4.expect("an IPv4 guest address");
        let mut device = GuestDevice(network.take_backend());
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress(bootstrap.mac))),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(ipv4.address.into(), ipv4.prefix_len))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(ipv4.gateway)
            .unwrap();
        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            gateway: ipv4.gateway,
            started: std::time::Instant::now(),
            next_port: 49152,
        }
    }

    /// Whether a new TCP connection from the guest to the host's `port` is established.
    async fn connects_to_host(&mut self, port: u16) -> bool {
        self.open_to_host(port).await.is_some()
    }

    /// A new TCP connection from the guest to the host's `port`, once established.
    async fn open_to_host(&mut self, port: u16) -> Option<SocketHandle> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1024]),
            tcp::SocketBuffer::new(vec![0; 1024]),
        );
        socket
            .connect(
                self.iface.context(),
                (IpAddress::from(self.gateway), port),
                self.next_port,
            )
            .unwrap();
        self.next_port += 1;
        let handle = self.sockets.add(socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            match self.sockets.get::<tcp::Socket>(handle).state() {
                tcp::State::Established => return Some(handle),
                tcp::State::Closed | tcp::State::TimeWait => return None,
                _ if tokio::time::Instant::now() >= deadline => return None,
                _ => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    }

    fn state(&mut self, handle: SocketHandle) -> tcp::State {
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.sockets.get::<tcp::Socket>(handle).state()
    }

    /// Whether the network ends this established connection within a few seconds.
    async fn ends(&mut self, handle: SocketHandle) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            if self.sockets.get::<tcp::Socket>(handle).state() != tcp::State::Established {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        false
    }
}

/// A host service the guest can dial through its gateway; it accepts every connection.
async fn host_service() -> u16 {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"ok").await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

fn running_network(policy: NetworkPolicy) -> SmoltcpNetwork {
    let mut config = NetworkConfig::default();
    config.tls.enabled = false;
    config.policy = policy;
    SmoltcpNetwork::build(
        config.resolve(&EnvNetworkSecretResolver).unwrap(),
        7,
        microsandbox_types::DeploymentProfile::SingleTenant,
        HostRoutes {
            ipv4: true,
            ipv6: false,
        },
    )
    .unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_set_on_a_running_network_decides_its_next_connection() {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    assert!(
        guest.connects_to_host(port).await,
        "the open policy refused the first connection"
    );
    policy.set(NetworkPolicy::none());
    assert!(
        !guest.connects_to_host(port).await,
        "a connection opened after the policy was closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_the_policy_ends_a_connection_it_now_denies() {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    let open = guest
        .open_to_host(port)
        .await
        .expect("the open policy refused it");
    policy.set(NetworkPolicy::none());
    assert!(
        guest.ends(open).await,
        "a connection the new policy denies stayed open"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn narrowing_leaves_open_a_connection_the_new_policy_still_allows() {
    let (kept_port, ended_port) = (host_service().await, host_service().await);
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    let kept = guest.open_to_host(kept_port).await.expect("refused");
    let ended = guest.open_to_host(ended_port).await.expect("refused");
    policy.set(
        NetworkPolicy::builder()
            .default_deny()
            .egress(|e| e.tcp().port(kept_port).allow_host())
            .build()
            .unwrap(),
    );
    assert!(guest.ends(ended).await, "the denied connection stayed open");
    assert_eq!(
        guest.state(kept),
        tcp::State::Established,
        "narrowing ended a connection the new policy still allows"
    );
}
