use fast_socks5::server::{run_tcp_proxy, DnsResolveHelper, Socks5ServerProtocol};
use fast_socks5::{ReplyError, Result, Socks5Command, SocksError};
use std::future::Future;
use std::net::SocketAddr::{V4, V6};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::util::target_addr::TargetAddr::Ip;
use tokio::net::TcpListener;
use tokio::task;
use tracing::{error, info, warn};

pub const SOCKS_LISTEN_ADDR: &str = "127.0.0.1:52923";
pub const ALL_IF_LISTEN_ADDR: &str = "0.0.0.0:52923";

pub async fn spawn_socks_server(loopback: bool) -> Result<()> {
    let listener = if loopback {
        TcpListener::bind(SOCKS_LISTEN_ADDR).await?
    } else {
        TcpListener::bind(ALL_IF_LISTEN_ADDR).await?
    };

    info!("Listen for socks connections @ {}", SOCKS_LISTEN_ADDR);

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(serve_socks5(socket));
            }
            Err(err) => {
                warn!("accept error = {:?}", err);
            }
        }
    }

}

const TIMEOUT: u64 = 30;
async fn serve_socks5(socket: tokio::net::TcpStream) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) =
        Socks5ServerProtocol::accept_no_auth(socket).await?
        .read_command()
        .await?
        .resolve_dns()
        .await?;

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

            run_tcp_proxy(proto, &target_addr, TIMEOUT, false).await?;
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
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{:#}", &err),
        }
    })
}