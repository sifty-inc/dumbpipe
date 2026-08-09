use fast_socks5::server::{run_tcp_proxy, DnsResolveHelper, Socks5ServerProtocol};
use fast_socks5::{ReplyError, Socks5Command, SocksError};
use std::future::Future;
use std::io;
use std::net::SocketAddr::{V4, V6};
use std::time::Duration;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::util::target_addr::TargetAddr::Ip;
use tokio::net::TcpListener;
use tokio::task;
use tracing::{error, info, warn};

pub const SOCKS_LISTEN_ADDR: &str = "127.0.0.1:52923";
pub const ALL_IF_LISTEN_ADDR: &str = "0.0.0.0:52923";

pub async fn spawn_socks_server(loopback: bool) -> Result<(), SocksError> {
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
                spawn_and_log_error(serve_socks5(socket));
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

async fn serve_socks5(socket: tokio::net::TcpStream) -> Result<(), SocksError> {
    let negotiate = async {
        Socks5ServerProtocol::accept_no_auth(socket).await?
            .read_command()
            .await?
            .resolve_dns()
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
            let mut deny_connection = false;
            if let Ip(ip) = target_addr {
                if let V4(s_ipv4) = ip {
                    let ipv4 = s_ipv4.ip();
                    if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_broadcast() || ipv4.is_link_local() {
                        deny_connection = true;
                    }
                } else if let V6(s_ipv6) = ip {
                    let ipv6 = s_ipv6.ip();
                    if ipv6.is_loopback() || ipv6.is_multicast() || ipv6.is_unique_local() || ipv6.is_unicast_link_local() {
                        deny_connection = true;
                    }
                }
            } else {
                deny_connection = true;
            }

            if deny_connection {
                warn!("Denied connection to {:?}", target_addr);
                return Err(ReplyError::ConnectionNotAllowed.into());
            }

            run_tcp_proxy(proto, &target_addr, Duration::from_secs(TIMEOUT), false).await?;
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