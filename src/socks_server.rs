use fast_socks5::server::{run_tcp_proxy, Socks5ServerProtocol};
use fast_socks5::{ReplyError, Socks5Command, SocksError};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use fast_socks5::util::target_addr::TargetAddr;
use iroh::dns::DnsResolver;
use tokio::net::TcpListener;
use tokio::task;
use tracing::{error, info, warn};

pub const SOCKS_LISTEN_ADDR: &str = "127.0.0.1:52923";
pub const ALL_IF_LISTEN_ADDR: &str = "0.0.0.0:52923";

pub async fn spawn_socks_server(loopback: bool, resolver: DnsResolver) -> Result<(), SocksError> {
    let listen_addr = if loopback {
        SOCKS_LISTEN_ADDR
    } else {
        ALL_IF_LISTEN_ADDR
    };
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Listen for socks connections @ {}", listen_addr);

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(serve_socks5(socket, resolver.clone()));
            }
            Err(err) => {
                warn!("accept error = {:?}", err);
                // Errors like EMFILE/ENFILE persist until a descriptor is freed, and
                // retrying immediately would spin the accept loop at full tilt. Back
                // off briefly so the runtime can make progress closing connections.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

}

/// Timeout for connecting out to the target of a `CONNECT` command.
const TIMEOUT: u64 = 30;
/// Timeout for a client to complete the socks5 greeting and command.
///
/// Without this a client that connects and then says nothing parks a descriptor
/// forever, since the negotiation below has no deadline of its own.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for resolving a single target hostname.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve a socks target to an address to dial.
///
/// This replaces fast-socks5's `resolve_dns()` helper, which calls `getaddrinfo`
/// through the blocking pool for every `CONNECT` and caches nothing. A browser
/// opens many sockets to the same handful of hosts, so that turns one page load
/// into dozens of identical queries against the upstream resolver, each holding a
/// blocking thread while it waits - enough, on a busy proxy, to swamp a consumer
/// router's DNS server and to fail with `Temporary failure in name resolution`.
/// The resolver passed in here caches answers for as long as their record TTL
/// allows, so repeat targets cost nothing.
async fn resolve_target(
    resolver: &DnsResolver,
    target: TargetAddr,
) -> Result<SocketAddr, ReplyError> {
    match target {
        TargetAddr::Ip(addr) => Ok(addr),
        TargetAddr::Domain(host, port) => {
            let addrs = resolver
                .lookup_ipv4_ipv6(host.clone(), DNS_TIMEOUT)
                .await
                .map_err(|cause| {
                    error!("DNS resolution failed for {}: {}", host, cause);
                    ReplyError::HostUnreachable
                })?;
            addrs
                .map(|ip| SocketAddr::new(ip, port))
                .next()
                .ok_or_else(|| {
                    error!("DNS returned no records for {}", host);
                    ReplyError::HostUnreachable
                })
        }
    }
}

/// Whether the proxy refuses to dial this address.
///
/// The proxy is reachable by anyone holding the ticket, so it must not be usable
/// to reach the host's own services or the rest of the network it sits on.
fn is_denied(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_broadcast() || ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

async fn serve_socks5(
    socket: tokio::net::TcpStream,
    resolver: DnsResolver,
) -> Result<(), SocksError> {
    let negotiate = async {
        Socks5ServerProtocol::accept_no_auth(socket).await?
            .read_command()
            .await
    };
    let (proto, cmd, target_addr) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate).await {
        Ok(res) => res?,
        Err(_) => {
            warn!("socks5 handshake timed out");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "socks5 handshake timed out").into());
        }
    };

    match cmd {
        Socks5Command::TCPConnect => {
            let addr = match resolve_target(&resolver, target_addr).await {
                Ok(addr) => addr,
                Err(reply) => {
                    proto.reply_error(&reply).await?;
                    return Err(reply.into());
                }
            };

            if is_denied(&addr) {
                warn!("Denied connection to {:?}", addr);
                proto.reply_error(&ReplyError::ConnectionNotAllowed).await?;
                return Err(ReplyError::ConnectionNotAllowed.into());
            }

            run_tcp_proxy(
                proto,
                &TargetAddr::Ip(addr),
                Duration::from_secs(TIMEOUT),
                false,
            )
            .await?;
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };
    Ok(())
}


fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<(), SocksError>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{:#}", &err),
        }
    })
}
