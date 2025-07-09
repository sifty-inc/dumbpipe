//! Command line arguments.

use crate::socks_server::SOCKS_LISTEN_ADDR;
use anyhow::Context;
use clap::{Parser, Subcommand};
use dumbpipe::{forward_bidi, get_or_create_secret, listen_tcp, setup_relay_if_specified, CommonArgs, ListenTcpArgs, NodeTicket, SocksServerForwardArgs};
use iroh::endpoint::Builder;
use iroh::{endpoint::Connecting, Endpoint, NodeAddr, RelayMap, RelayMode, SecretKey};
use iroh_base::RelayUrl;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::io::Read;
use std::process::exit;
use std::time::Duration;
use std::{fs, io, net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs}, str::FromStr};
use tokio::fs::File;
use tokio::time::sleep;
use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt}, select, time};
use tokio_util::sync::CancellationToken;
use toml::de::Error;
use tracing::{error, info, warn};

mod socks_server;

/// Create a dumb pipe between two machines, using an iroh magicsocket.
///
/// One side listens, the other side connects. Both sides are identified by a
/// 32 byte node id.
///
/// Connecting to a node id is independent of its IP address. Dumbpipe will try
/// to establish a direct connection even through NATs and firewalls. If that
/// fails, it will fall back to using a relay server.
///
/// For all subcommands, you can specify a secret key using the IROH_SECRET
/// environment variable. If you don't, a random one will be generated.
///
/// You can also specify a port for the magicsocket. If you don't, a random one
/// will be chosen.
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on a magicsocket and forward stdin/stdout to the first incoming
    /// bidi stream.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    Listen(ListenArgs),

    /// Listen on a magicsocket and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a node ticket on stderr that can be used to connect.
    ///
    /// As far as the magic socket is concerned, this is listening. But it is
    /// connecting to a TCP socket for which you have to specify the host and port.
    ListenTcp(ListenTcpArgs),

    /// The same as listen tcp, but automatically connects to 127.0.0.1:1080
    SocksServerForward(SocksServerForwardArgs),

    // Only do socks proxy
    SocksOnly(CommonArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout.
    ///
    /// A node ticket is required to connect.
    Connect(ConnectArgs),

    /// Connect to a magicsocket, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A node ticket is required to connect.
    ///
    /// As far as the magic socket is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the interface and port.
    ConnectTcp(ConnectTcpArgs),

    /// Generate a secret to be used with dumbpipe, provide as IROH_SECRET
    GenSecret(CommonArgs),
}




#[derive(Parser, Debug)]
pub struct ListenArgs {
    #[clap(flatten)]
    pub common: CommonArgs,
}




#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// The addresses to listen on for incoming tcp connections.
    ///
    /// To listen on all network interfaces, use 0.0.0.0:12345
    #[clap(long)]
    pub addr: String,

    /// The node to connect to
    pub ticket: NodeTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The node to connect to
    pub ticket: NodeTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}



/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair, aborting both sides when either one forwarder is done,
/// or when control-c is pressed.
async fn listen_stdio(args: ListenArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder()
        .alpns(vec![args.common.alpn()?])
        .secret_key(secret_key);
    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    // wait for the endpoint to figure out its address before making a ticket
    endpoint.home_relay().initialized().await?;
    let node = endpoint.node_addr().await?;
    let mut short = node.clone();
    let ticket = NodeTicket::new(node);
    short.direct_addresses.clear();
    let short = NodeTicket::new(short);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    info!("Listening. To connect, use:\ndumbpipe connect {}", ticket);
    if args.common.verbose > 0 {
        info!("or:\ndumbpipe connect {}", short);
    }

    loop {
        let Some(connecting) = endpoint.accept().await else {
            break;
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_node_id = &connection.remote_node_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = match connection.accept_bi().await {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting stream: {}", cause);
                // if accept_bi fails, we want to continue accepting connections
                continue;
            }
        };
        tracing::debug!("accepted bidi stream from {}", remote_node_id);
        if !args.common.is_custom_alpn() {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
        // stop accepting connections after the first successful one
        break;
    }
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> anyhow::Result<()> {
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder().secret_key(secret_key).alpns(vec![]);

    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }
    let endpoint = builder.bind().await?;
    let addr = args.ticket.node_addr();
    let remote_node_id = addr.node_id;
    // connect to the node, try only once
    let connection = endpoint.connect(addr.clone(), &args.common.alpn()?).await?;
    tracing::info!("connected to {}", remote_node_id);
    // open a bidi stream, try only once
    let (mut s, r) = connection.open_bi().await?;
    tracing::info!("opened bidi stream to {}", remote_node_id);
    // send the handshake unless we are using a custom alpn
    // when using a custom alpn, evertyhing is up to the user
    if !args.common.is_custom_alpn() {
        // the connecting side must write first. we don't know if there will be something
        // on stdin, so just write a handshake.
        s.write_all(&dumbpipe::HANDSHAKE).await?;
    }
    tracing::info!("forwarding stdin/stdout to {}", remote_node_id);
    forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    tokio::io::stdout().flush().await?;
    Ok(())
}

/// Listen on a tcp port and forward incoming connections to a magicsocket.
async fn connect_tcp(args: ConnectTcpArgs) -> anyhow::Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let mut builder = Endpoint::builder().alpns(vec![]).secret_key(secret_key);

    builder = setup_relay_if_specified(builder);

    if let Some(addr) = args.common.magic_ipv4_addr {
        builder = builder.bind_addr_v4(addr);
    }
    if let Some(addr) = args.common.magic_ipv6_addr {
        builder = builder.bind_addr_v6(addr);
    }


    let endpoint = builder.bind().await.context("unable to bind magicsock")?;
    tracing::info!("node id {}",  endpoint.node_id());

    let e_clone = endpoint.clone();

    tokio::spawn( async move {
        loop {
            let mut map = Map::new();
            for e in e_clone.remote_info_iter() {
                map.insert(e.node_id.to_string(), Value::String(e.conn_type.to_string()));
            }
            let obj = Value::Object(map);
            eprintln!("{obj}");
            sleep(Duration::from_secs(10)).await;
        }

    });





    tracing::info!("tcp listening on {:?}", addrs);
    let tcp_listener = match tokio::net::TcpListener::bind(addrs.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", addrs, cause);
            return Ok(());
        }
    };
    async fn handle_tcp_accept(
        next: io::Result<(tokio::net::TcpStream, SocketAddr)>,
        addr: NodeAddr,
        endpoint: Endpoint,
        handshake: bool,
        alpn: &[u8],
    ) -> anyhow::Result<()> {
        let (tcp_stream, tcp_addr) = next.context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let remote_node_id = addr.node_id;
        let connection = endpoint
            .connect(addr, alpn)
            .await
            .context(format!("error connecting to {}", remote_node_id))?;
        let (mut magic_send, magic_recv) = connection
            .open_bi()
            .await
            .context(format!("error opening bidi stream to {}", remote_node_id))?;
        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, evertyhing is up to the user
        if handshake {
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            magic_send.write_all(&dumbpipe::HANDSHAKE).await?;
        }
        forward_bidi(tcp_recv, tcp_send, magic_recv, magic_send).await?;
        anyhow::Ok(())
    }
    let addr = args.ticket.node_addr();
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let endpoint = endpoint.clone();
        let addr = addr.clone();
        let handshake = !args.common.is_custom_alpn();
        let alpn = args.common.alpn()?;
        tokio::spawn(async move {
            if let Err(cause) = handle_tcp_accept(next, addr, endpoint, handshake, &alpn).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}



async fn check_auto_shutdown(options: &CommonArgs) {
    if let Some(secs) = options.auto_shutdown {
        info!("Will automatically shutdown in {} seconds", secs);
        tokio::spawn(async move {
            sleep(Duration::from_secs(secs as u64)).await;
            info!("Auto shutdown happening NOW");
            exit(0);
        });
    }
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("dumbpipe=info,dumbpipe::socks_server=info")
        .init();
    let args = Args::try_parse();
    info!("Dumbpipe starting, version {}", env!("VERGEN_RUSTC_COMMIT_HASH"));

    if let Ok(args) = args {
        let res = match args.command {
            Commands::Listen(args) => listen_stdio(args).await,
            Commands::ListenTcp(args) => {
                check_auto_shutdown(&args.common).await;
                listen_tcp(args, false, None).await
            },
            Commands::SocksServerForward(args) => {
                check_auto_shutdown(&args.common).await;
                let listen_args = ListenTcpArgs { host: String::from(SOCKS_LISTEN_ADDR), common: args.common, ticket_out_path: args.ticket_out_path  };
                listen_tcp(listen_args, true, None).await
            },
            Commands::SocksOnly(_args) => {
                socks_server::spawn_socks_server(false).await?;
                Ok(())
            },
            Commands::Connect(args) => connect_stdio(args).await,
            Commands::ConnectTcp(args) => connect_tcp(args).await,
            Commands::GenSecret(_) => {
                let key = SecretKey::generate(rand::rngs::OsRng);
                println!("{}", key);
                exit(0)
            }
        };
        match res {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1)
            }
        }
    } else {
        info!("{:?}", args);
        info!("NO VALID COMMAND SUPPLIED, operating in socks server forward mode");
        // no command was specified in the arguments, run the server socks command
        let listen_args = ListenTcpArgs { host: String::from(SOCKS_LISTEN_ADDR), ticket_out_path: None, common: CommonArgs {
            magic_ipv4_addr: None,
            magic_ipv6_addr: None,
            custom_alpn: None,
            verbose: 0,
            auto_shutdown: None
        } };
        listen_tcp(listen_args, true, None).await.expect("listen failed")
    };
    info!("Dumbpipe exiting");
    Ok(())
}
