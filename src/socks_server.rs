use fast_socks5::server::{run_tcp_proxy, DnsResolveHelper, Socks5ServerProtocol};
use fast_socks5::{ReplyError, Result, Socks5Command, SocksError};
use std::future::Future;
use tokio::net::TcpListener;
use tokio::task;
use tracing::{error, info, warn};

pub const SOCKS_LISTEN_ADDR: &str = "127.0.0.1:1080";

pub(crate) async fn spawn_socks_server() -> Result<()> {
    let listener = TcpListener::bind(SOCKS_LISTEN_ADDR).await?;

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