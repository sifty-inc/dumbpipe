use fast_socks5::{
    server::{Config, SimpleUserPassword, Socks5Server, Socks5Socket},
    Result
};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio_stream::StreamExt;
use tracing::{info, warn};

const LISTEN_ADDR: &str = "127.0.0.1:1080";

pub(crate) async fn spawn_socks_server() -> Result<()> {
    let listener = <Socks5Server>::bind(LISTEN_ADDR).await?;
    let listener = listener.with_config(Config::default());

    let mut incoming = listener.incoming();

    info!("Listen for socks connections @ {}", LISTEN_ADDR);

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {

                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => {
                warn!("accept error = {:?}", err);
            }
        }
    }

    Ok(())
}

fn spawn_and_log_error<F, T>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<Socks5Socket<T, SimpleUserPassword>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    task::spawn(async move {
        match fut.await {
            Ok(mut socket) => {
                if let Some(user) = socket.take_credentials() {
                    info!("user logged in with `{}`", user.username);
                }
            }
            Err(err) => warn!("{:#}", &err),
        }
    })
}
