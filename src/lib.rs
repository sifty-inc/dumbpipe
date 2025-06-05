/// The ALPN for dumbpipe.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send a fixed size handshake to make sure the stream is created.
pub const ALPN: &[u8] = b"DUMBPIPEV0";

/// The handshake to send when connecting.
///
/// The side that calls open_bi() first must send this handshake, the side that
/// calls accept_bi() must consume it.
pub const HANDSHAKE: [u8; 5] = *b"hello";
use anyhow::Context;
use clap::Parser;
use iroh::endpoint::{Builder, Connecting};
use iroh::{Endpoint, RelayMap, RelayMode};
pub use iroh_base::ticket::NodeTicket;
use iroh_base::{RelayUrl, SecretKey};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::io::Read;
use std::net::{SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::process::exit;
use std::str::FromStr;
use std::time::Duration;
use std::{fs, io};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::{select, time};
use tokio_util::sync::CancellationToken;
use toml::de::Error;
use tracing::log::warn;
use tracing::{error, info};

mod socks_server;

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    #[clap(long)]
    pub host: String,

    #[clap(flatten)]
    pub common: CommonArgs,

    #[clap(long)]
    pub ticket_out_path: Option<String>,
}


#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The IPv4 address that magicsocket will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub magic_ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that magicsocket will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub magic_ipv6_addr: Option<SocketAddrV6>,

    /// A custom ALPN to use for the magicsocket.
    ///
    /// This is an expert feature that allows dumbpipe to be used to interact
    /// with existing iroh protocols.
    ///
    /// When using this option, the connect side must also specify the same ALPN.
    /// The listen side will not expect a handshake, and the connect side will
    /// not send one.
    ///
    /// Alpns are byte strings. To specify an utf8 string, prefix it with `utf8:`.
    /// Otherwise, it will be parsed as a hex string.
    #[clap(long)]
    pub custom_alpn: Option<String>,

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl CommonArgs {
    pub fn alpn(&self) -> anyhow::Result<Vec<u8>> {
        Ok(match &self.custom_alpn {
            Some(alpn) => parse_alpn(alpn)?,
            None => ALPN.to_vec(),
        })
    }

    pub fn is_custom_alpn(&self) -> bool {
        self.custom_alpn.is_some()
    }
}

#[derive(Parser, Debug)]
pub struct SocksServerForwardArgs {
    #[clap(flatten)]
    pub common: CommonArgs,

    #[clap(long)]
    pub ticket_out_path: Option<String>,
}


fn parse_alpn(alpn: &str) -> anyhow::Result<Vec<u8>> {
    Ok(if let Some(text) = alpn.strip_prefix("utf8:") {
        text.as_bytes().to_vec()
    } else {
        hex::decode(alpn)?
    })
}

#[derive(Deserialize)]
struct SocksForwardConfig {
    mothership_url: Option<String>,
    proxy_name: Option<String>,
    iroh_secret: Option<String>
}

fn read_file_if_exists(path: &str) -> Option<String> {
    if let Ok(mut file) = fs::File::open(path) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            Some(contents)
        } else {
            None
        }
    } else {
        None
    }
}



fn try_load_config_from_file() -> Option<SocksForwardConfig> {
    let filedata = read_file_if_exists("./config.toml");
    if let Some(filedata) = filedata {
        let cfg: Result<SocksForwardConfig, Error> = toml::from_str(&filedata);
        cfg.ok()
    } else {
        None
    }
}

pub fn setup_relay_if_specified(mut builder: Builder) -> Builder {
    match std::env::var("IROH_RELAY_URL") {
        Ok(url) => {
            match Url::parse(&url) {
                Ok(url) => {
                    let relay_url: RelayUrl = url.into();
                    let relay_map: RelayMap = relay_url.into();
                    builder = builder.relay_mode(RelayMode::Custom(relay_map));
                }
                _ => {
                    tracing::error!("invalid IROH_RELAY_URL: {}", url);
                }
            };
        },
        Err(_) => {}
    };
    builder

}


pub fn get_or_create_secret() -> anyhow::Result<SecretKey> {
    match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret).context("invalid secret"),
        Err(_) => {
            let key = SecretKey::generate(rand::rngs::OsRng);
            info!("using secret key {}", key);
            Ok(key)
        }
    }
}


/// Copy from a reader to a quinn stream.
///
/// Will send a reset to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_to_quinn(
    mut from: impl AsyncRead + Unpin,
    mut send: quinn::SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tracing::trace!("copying to quinn");
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            send.finish()?;
            Ok(size)
        }
        _ = token.cancelled() => {
            // send a reset to the other side immediately
            send.reset(0u8.into()).ok();
            Err(io::Error::new(io::ErrorKind::Other, "cancelled"))
        }
    }
}

/// Copy from a quinn stream to a writer.
///
/// Will send stop to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_from_quinn(
    mut recv: quinn::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => {
            Ok(res?)
        },
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::new(io::ErrorKind::Other, "cancelled"))
        }
    }
}


pub async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: quinn::RecvStream,
    to2: quinn::SendStream,
) -> anyhow::Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let forward_from_stdin = tokio::spawn(async move {
        copy_to_quinn(from1, to2, token1.clone())
            .await
            .map_err(cancel_token(token1))
    });
    let forward_to_stdout = tokio::spawn(async move {
        copy_from_quinn(from2, to1, token2.clone())
            .await
            .map_err(cancel_token(token2))
    });
    let _control_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });
    forward_to_stdout.await??;
    forward_from_stdin.await??;
    Ok(())
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.


fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

/// Listen on a magicsocket and forward incoming connections to a tcp socket.
pub async fn listen_tcp(args: ListenTcpArgs, do_socks: bool) -> anyhow::Result<()> {
    let file_cfg = try_load_config_from_file();

    if do_socks {
        tokio::spawn(async {
            socks_server::spawn_socks_server().await.expect("Failed to start SOCKS5 server");
        });
    }

    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.host, e),
    };
    let secret_key: SecretKey = match &file_cfg {
        Some(cfg) => {
            if let Some(sec) = cfg.iroh_secret.as_ref() {
                info!("Loaded secret key from file");
                SecretKey::from_str(sec.as_str()).context("invalid secret")?
            } else {
                get_or_create_secret()?
            }
        },
        _ => get_or_create_secret()?
    };
    info!("Listening on {}", secret_key);

    let mut builder = Endpoint::builder()
        .alpns(vec![args.common.alpn()?])
        .secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    builder = setup_relay_if_specified(builder);

    let endpoint = builder.bind().await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.home_relay().initialized().await?;
    let node_addr = endpoint.node_addr().await?;
    let mut short = node_addr.clone();
    let ticket = NodeTicket::new(node_addr);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    info!("Forwarding incoming requests to '{}'.", args.host);
    info!("To connect, use e.g.:");
    info!("dumbpipe connect-tcp {ticket}");
    if args.common.verbose > 0 {
        info!("or:\ndumbpipe connect-tcp {}", short);
    }
    info!("node id is {}", ticket.node_addr().node_id);
    info!("derp url is {:?}", ticket.node_addr().relay_url);


    let ticket_s = ticket.to_string();

    if let Some(ticket_out) = &args.ticket_out_path {
        let mut file = File::create(ticket_out).await?;
        file.write_all(ticket_s.as_bytes()).await?;
    }

    let mothership: Option<String> = match std::env::var("MOTHERSHIP_URL") {
        Ok(url) => Some(url),
        Err(_) =>  {
            match &file_cfg {
                None => None,
                Some(ref c) => {
                    c.mothership_url.clone()
                }
            }
        }
    };

    let proxy_name: Option<String> = match std::env::var("PROXY_NAME") {
        Ok(url) => Some(url),
        Err(_) =>  {
            match &file_cfg {
                None => None,
                Some(ref c) => {
                    c.proxy_name.clone()
                }
            }
        }
    };


    if let Some(mothership) = mothership {
        let checkin_internval = match std::env::var("MOTHERSHIP_UPDATE_INTERVAL_SECS") {
            Ok(val) => u64::from_str_radix(&val, 10).expect("Invalid mothership update interval"),
            Err(_) => 60
        };
        let name = match proxy_name {
            Some(name) => name,
            None => {
                error!("PROXY_NAME is required with mothership");
                exit(1)
            }
        };
        info!("Proxy name: {name}");
        info!("Will check in with mothership at {}, interval: {}", &mothership, checkin_internval);
        let e_clone = endpoint.clone();
        tokio::spawn( async move {
            let client = reqwest::Client::new();
            loop {
                let mut map = Map::new();
                for e in e_clone.remote_info_iter() {
                    if let Some(last_rec) = e.last_received() {
                        if last_rec < Duration::from_secs(20) {
                            map.insert(e.node_id.to_string(), Value::String(e.conn_type.to_string()));
                        }
                    }
                }
                let obj = Value::Object(map);

                let params = [("name", name.as_str()), ("ticket", &ticket_s), ("connections", &obj.to_string())];
                info!("connection data: {}", &obj.to_string());

                let res = client.post(&mothership)
                    .form(&params)
                    .send()
                    .await;

                match res {
                    Ok(res) => {
                        match res.status() {
                            StatusCode::OK => {
                                info!("Checked in with mothership");
                                let x = res.text().await;
                                if let Ok(x) = x {
                                    info!("result is {x}")
                                }

                            },
                            StatusCode::GONE => {
                                error!("Mothership sent status 410: Gone, shutting down");
                                exit(1)
                            },
                            status_code => {
                                let res = res.text().await.unwrap_or(String::from("unknown"));
                                error!("Check in failed, will retry. Got status code {status_code}: {res}");
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Could not connect to mothership {:?}", e)
                    }
                }

                time::sleep(Duration::from_secs(checkin_internval)).await;
            }
        });
    } else {
        warn!("No mothership supplied");
    }





    // handle a new incoming connection on the magic endpoint
    async fn handle_magic_accept(
        connecting: Connecting,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
    ) -> anyhow::Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_node_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::debug!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; HANDSHAKE.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == HANDSHAKE, "invalid handshake");
        }
        let connection = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .context(format!("error connecting to {:?}", addrs))?;
        let (read, write) = connection.into_split();
        forward_bidi(read, write, r, s).await?;
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                info!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let addrs = addrs.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            if let Err(cause) = handle_magic_accept(connecting, addrs, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}