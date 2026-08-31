//! Command line arguments.
use std::{fs, io, net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs}, str::FromStr, time::Duration};
use std::io::Read;
use std::process::exit;
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use dumbpipe::EndpointTicket;
use iroh::{
    dns::DnsResolver,
    endpoint::{presets, Accepting, Connection, QuicTransportConfig, TransportAddrUsage},
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
};
use std::sync::{Arc, Mutex, OnceLock};
use n0_error::{bail_any, ensure_any, AnyError, Result, StdResultExt};
use reqwest::StatusCode;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    select,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
#[cfg(unix)]
use {
    std::path::PathBuf,
    tokio::net::{UnixListener, UnixStream},
};
use serde::Deserialize;
use tokio::time::sleep;
use serde_json::{Map, Value};
use crate::socks_server::SOCKS_LISTEN_ADDR;

mod socks_server;


#[derive(Deserialize)]
pub struct SocksForwardConfig {
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
        let cfg: Result<SocksForwardConfig, toml::de::Error> = toml::from_str(&filedata);
        cfg.ok()
    } else {
        None
    }
}


const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);

/// Create a dumb pipe between two machines, using an iroh endpoint.
///
/// One side listens, the other side connects. Both sides are identified by a
/// 32 byte endpoint id.
///
/// Connecting to a endpoint id is independent of its IP address. Dumbpipe will try
/// to establish a direct connection even through NATs and firewalls. If that
/// fails, it will fall back to using a relay server.
///
/// For all subcommands, you can specify a secret key using the IROH_SECRET
/// environment variable. If you don't, a random one will be generated.
///
/// You can also specify a port for the endpoint. If you don't, a random one
/// will be chosen.
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a short endpoint ticket. This ticket can be used to later connect to a
    /// listener that is using the same secret key again.
    ///
    /// This command only really makes sense when you are providing dumbpipe with a
    /// secret key.
    GenerateTicket,

    /// Listen on an endpoint and forward stdin/stdout to the first incoming
    /// bidi stream.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    Listen(ListenArgs),

    /// Listen on an endpoint and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a TCP socket for which you have to specify the host and port.
    ListenTcp(ListenTcpArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout.
    ///
    /// A endpoint ticket is required to connect.
    Connect(ConnectArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A endpoint ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the interface and port.
    ConnectTcp(ConnectTcpArgs),

    #[cfg(unix)]
    /// Listen on an endpoint and forward incoming connections to the specified
    /// Unix socket path. Every incoming bidi stream is forwarded to a new connection.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a Unix socket for which you have to specify the path.
    ListenUnix(ListenUnixArgs),

    #[cfg(unix)]
    /// Connect to an endpoint, open a bidi stream, and forward connections
    /// from the specified Unix socket path.
    ///
    /// A endpoint ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a Unix socket for which you have to specify the path.
    ConnectUnix(ConnectUnixArgs),

    // Only do socks proxy
    SocksOnly(CommonArgs),
    GenSecret(CommonArgs),
    /// The same as listen tcp, but automatically connects socksproxy
    SocksServerForward(SocksServerForwardArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed
    /// port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// A custom ALPN to use for the endpoint.
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

    #[clap(long)]
    pub auto_shutdown: Option<u32>,

    /// Close a forwarded connection after this many seconds with no data moving
    /// in either direction. 0 disables the timeout.
    ///
    /// Only applies to the tcp forwarding modes. A connection whose peer went
    /// away without closing cleanly would otherwise be held open forever,
    /// pinning its descriptors and buffers for the life of the process.
    #[clap(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
    pub idle_timeout: u64,

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Default seconds a forwarded connection may sit with no data moving.
///
/// Long enough not to disturb ordinary traffic - browser keep-alives idle out
/// well before this, and websockets that ping stay active - while still
/// reclaiming connections whose peer vanished without closing.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;

impl CommonArgs {
    /// The configured idle timeout, or `None` if it is disabled.
    fn idle_timeout(&self) -> Option<Duration> {
        match self.idle_timeout {
            0 => None,
            secs => Some(Duration::from_secs(secs)),
        }
    }
}

impl CommonArgs {
    fn alpn(&self) -> Result<Vec<u8>> {
        Ok(match &self.custom_alpn {
            Some(alpn) => parse_alpn(alpn)?,
            None => dumbpipe::ALPN.to_vec(),
        })
    }

    fn is_custom_alpn(&self) -> bool {
        self.custom_alpn.is_some()
    }
}

fn parse_alpn(alpn: &str) -> Result<Vec<u8>> {
    Ok(if let Some(text) = alpn.strip_prefix("utf8:") {
        text.as_bytes().to_vec()
    } else {
        hex::decode(alpn).anyerr()?
    })
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

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
pub struct ConnectTcpArgs {
    /// The addresses to listen on for incoming tcp connections.
    ///
    /// To listen on all network interfaces, use 0.0.0.0:12345
    #[clap(long)]
    pub addr: String,

    /// The endpoint to connect to
    pub ticket: EndpointTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The endpoint to connect to
    pub ticket: EndpointTicket,

    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct SocksServerForwardArgs {
    #[clap(flatten)]
    pub common: CommonArgs,

    #[clap(long)]
    pub ticket_out_path: Option<String>,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ListenUnixArgs {
    /// Path to the Unix socket to connect to
    #[clap(long)]
    pub socket_path: PathBuf,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ConnectUnixArgs {
    /// Path to the Unix socket to listen on
    #[clap(long)]
    pub socket_path: PathBuf,

    /// The endpoint to connect to
    pub ticket: EndpointTicket,

    #[clap(flatten)]
    pub common: CommonArgs,
}

/// When either direction of a forwarded connection last moved data.
///
/// Both directions share one of these, so "idle" means nothing has moved either
/// way - a download that is quiet only because the client has nothing to say
/// keeps the connection alive.
#[derive(Debug)]
struct Activity {
    /// Milliseconds since `start` at which data last moved.
    last: std::sync::atomic::AtomicU64,
    start: std::time::Instant,
}

impl Activity {
    fn new() -> Self {
        Self {
            last: std::sync::atomic::AtomicU64::new(0),
            start: std::time::Instant::now(),
        }
    }

    fn touch(&self) {
        let now = self.start.elapsed().as_millis() as u64;
        self.last
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(std::sync::atomic::Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }
}

/// Size of the per-direction copy buffer.
///
/// Two of these are live per forwarded connection, so this trades throughput
/// against the memory held by all the connections in flight at once.
const COPY_BUF_SIZE: usize = 16 * 1024;

/// `tokio::io::copy`, but recording progress as it goes.
///
/// The stock copy reports nothing until it finishes, which is no use for
/// noticing that a connection has gone quiet while it is still running.
async fn copy_tracking(
    from: &mut (impl AsyncRead + Unpin),
    to: &mut (impl AsyncWrite + Unpin),
    activity: &Activity,
) -> io::Result<u64> {
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; COPY_BUF_SIZE];
    let mut copied = 0u64;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            to.flush().await?;
            return Ok(copied);
        }
        to.write_all(&buf[..n]).await?;
        copied += n as u64;
        activity.touch();
    }
}

/// Copy from a reader to a noq stream.
///
/// Will send a reset to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_to_noq(
    mut from: impl AsyncRead + Unpin,
    mut send: noq::SendStream,
    token: CancellationToken,
    activity: Arc<Activity>,
) -> io::Result<u64> {
    tracing::trace!("copying to noq");
    tokio::select! {
        res = copy_tracking(&mut from, &mut send, &activity) => {
            let size = res?;
            send.finish()?;
            Ok(size)
        }
        _ = token.cancelled() => {
            // send a reset to the other side immediately
            send.reset(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Copy until EOF, then shut the writer down.
///
/// `tokio::io::copy` flushes the writer but never shuts it down, so on its own it
/// does not turn the reader's EOF into a FIN on the destination socket. The peer
/// would then wait for data that is never coming, neither side would ever close,
/// and both descriptors would stay pinned for the lifetime of the process.
async fn copy_and_shutdown(
    from: &mut (impl AsyncRead + Unpin),
    to: &mut (impl AsyncWrite + Unpin),
    activity: &Activity,
) -> io::Result<u64> {
    let size = copy_tracking(from, to, activity).await?;
    // best effort: the peer may already be gone, which is not an error here
    to.shutdown().await.ok();
    Ok(size)
}

/// Copy from a noq stream to a writer.
///
/// Will send stop to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_from_noq(
    mut recv: noq::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
    activity: Arc<Activity>,
) -> io::Result<u64> {
    tokio::select! {
        res = copy_and_shutdown(&mut recv, &mut to, &activity) => res,
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.
fn get_or_create_secret() -> Result<SecretKey> {
    match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret).std_context("invalid secret"),
        Err(_) => {
            let key = SecretKey::generate();
            eprintln!(
                "using secret key {}",
                data_encoding::HEXLOWER.encode(&key.to_bytes())
            );
            Ok(key)
        }
    }
}

/// Raise the open file limit towards the hard limit.
///
/// Every proxied connection costs three descriptors on the forwarding host: the
/// loopback pair between the pipe and the socks server, plus the socks server's
/// outbound socket. The usual 1024 soft limit is therefore exhausted by a few
/// hundred concurrent connections, which surfaces as
/// `accept error = ... Too many open files`. The soft limit can be raised up to
/// the hard limit without privileges, so do it here rather than relying on every
/// launcher to set `ulimit -n` or `LimitNOFILE`.
#[cfg(unix)]
fn raise_nofile_limit() {
    // Deliberately below a typical hard limit: this is already far more than the
    // proxy needs, and very large values upset code that sizes tables by
    // RLIMIT_NOFILE.
    const NOFILE_TARGET: libc::rlim_t = 65536;

    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes into the rlimit we hand it.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        tracing::warn!(
            "could not read open file limit: {}",
            io::Error::last_os_error()
        );
        return;
    }

    let target = NOFILE_TARGET.min(limit.rlim_max);
    if limit.rlim_cur >= target {
        tracing::info!("open file limit is {}", limit.rlim_cur);
        return;
    }

    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit only reads the rlimit we hand it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        tracing::warn!(
            "could not raise open file limit from {} to {}: {}",
            limit.rlim_cur,
            target,
            io::Error::last_os_error()
        );
        return;
    }
    tracing::info!(
        "raised open file limit from {} to {}",
        limit.rlim_cur,
        target
    );
}

#[cfg(not(unix))]
fn raise_nofile_limit() {}

/// Transport settings for a pipe that carries many concurrent streams.
///
/// The defaults are tuned for a handful of fat streams: 100 concurrent bidi
/// streams, and a 1.25MB receive window *per stream* with no cap on the
/// connection as a whole. Now that every forwarded TCP connection is a stream on
/// one shared connection rather than a connection of its own, that shape is
/// wrong in both directions - the stream count is too low and the per-stream
/// buffer is far too large. Allow many more streams, give each a window sized
/// for ordinary web traffic, and cap the connection total so worst-case memory
/// stays bounded no matter how many streams are live.
fn transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(CONNECTION_RECEIVE_WINDOW.into())
        .build()
}

/// Maximum forwarded TCP connections in flight on one pipe.
const MAX_CONCURRENT_STREAMS: u32 = 512;
/// Per-stream receive window. 512KB still saturates a ~40Mbps stream at 100ms
/// RTT, which is ample for proxied traffic.
const STREAM_RECEIVE_WINDOW: u32 = 512 * 1024;
/// Cap on data buffered across all streams of a connection, so the worst case is
/// bounded by this rather than by `MAX_CONCURRENT_STREAMS * STREAM_RECEIVE_WINDOW`.
const CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Create a new iroh endpoint.
async fn create_endpoint(
    secret_key: SecretKey,
    common: &CommonArgs,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .transport_config(transport_config())
        .alpns(alpns);
    if let Some(addr) = common.ipv4_addr {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(addr) = common.ipv6_addr {
        builder = builder.bind_addr(addr)?;
    }
    let endpoint = builder.bind().await.anyerr()?;
    Ok(endpoint)
}

/// A process-wide token that is cancelled when control-c is pressed.
///
/// Spawning a `ctrl_c()` watcher per forwarded connection leaks a task and a
/// signal registration for every connection the process ever handles, so a
/// single watcher is installed and hands out child tokens instead. Child tokens
/// are unregistered when they are dropped, so they do not accumulate.
fn shutdown_token() -> &'static CancellationToken {
    static SHUTDOWN: OnceLock<CancellationToken> = OnceLock::new();
    SHUTDOWN.get_or_init(|| {
        let token = CancellationToken::new();
        let watcher = token.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                watcher.cancel();
            }
        });
        token
    })
}

/// How often the idle watchdog wakes to check a connection.
///
/// The check is a single atomic load, so this only bounds how far past the
/// timeout a dead connection can linger.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Bidirectionally forward data from a noq stream and an arbitrary tokio
/// reader/writer pair.
///
/// A direction that ends cleanly propagates the half-close to its peer and lets
/// the other direction keep running, so long downloads survive a client that is
/// done sending. A direction that fails - or panics - cancels its sibling, so a
/// broken connection never leaves the other half parked on a descriptor.
///
/// `idle_timeout` bounds how long the pair may sit with no data moving in either
/// direction. Without it, a connection whose other half went away without a
/// clean close - one direction ends cleanly and the other simply never sees EOF
/// - parks forever: nothing cancels it, and QUIC's own idle timeout never fires
/// because the connection keep-alive is still running. Those parked forwarders
/// are what accumulate as descriptors and memory over a long-running proxy.
/// Pass `None` for interactive pipes, where sitting idle is normal and expected.
async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: noq::RecvStream,
    to2: noq::SendStream,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    let token1 = shutdown_token().child_token();
    let token2 = token1.clone();
    let activity = Arc::new(Activity::new());
    let activity2 = Arc::clone(&activity);

    // Cancelled when this function returns, by whichever path, so the watchdog
    // below never outlives the connection it is watching.
    let done = CancellationToken::new();
    let _done_guard = done.clone().drop_guard();

    if let Some(idle_timeout) = idle_timeout {
        let token = token1.clone();
        let activity = Arc::clone(&activity);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = done.cancelled() => return,
                    _ = tokio::time::sleep(IDLE_CHECK_INTERVAL) => {}
                }
                if activity.idle_for() >= idle_timeout {
                    tracing::info!(
                        "closing connection idle for {:?}",
                        activity.idle_for()
                    );
                    // cancels both directions, which reset/stop their streams
                    token.cancel();
                    return;
                }
            }
        });
    }

    let forward_from_stdin = tokio::spawn(async move {
        let guard = token1.clone().drop_guard();
        let res = copy_to_noq(from1, to2, token1, activity).await;
        if res.is_ok() {
            // clean EOF: let the other direction drain
            guard.disarm();
        }
        res
    });
    let forward_to_stdout = tokio::spawn(async move {
        let guard = token2.clone().drop_guard();
        let res = copy_from_noq(from2, to1, token2, activity2).await;
        if res.is_ok() {
            guard.disarm();
        }
        res
    });
    forward_to_stdout.await.anyerr()?.anyerr()?;
    forward_from_stdin.await.anyerr()?.anyerr()?;
    Ok(())
}

async fn listen_stdio(args: ListenArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its home relay and addresses before making a ticket
    if (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    let short = create_short_ticket(&addr);
    let ticket = EndpointTicket::new(addr);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Listening. To connect, use:\ndumbpipe connect {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect {short}");
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
        let remote_endpoint_id = &connection.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let (s, mut r) = match connection.accept_bi().await {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting stream: {}", cause);
                // if accept_bi fails, we want to continue accepting connections
                continue;
            }
        };
        tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
        if !args.common.is_custom_alpn() {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.anyerr()?;
            ensure_any!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        if args.recv_only {
            tracing::info!(
                "forwarding stdout to {} (ignoring stdin)",
                remote_endpoint_id
            );
            forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s, None).await?;
        } else {
            tracing::info!("forwarding stdin/stdout to {}", remote_endpoint_id);
            forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s, None).await?;
        }
        // stop accepting connections after the first successful one
        break;
    }
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![]).await?;
    let addr = args.ticket.endpoint_addr();
    let remote_endpoint_id = addr.id;
    // connect to the remote, try only once
    let connection = endpoint
        .connect(addr.clone(), &args.common.alpn()?)
        .await
        .anyerr()?;
    tracing::info!("connected to {}", remote_endpoint_id);
    // open a bidi stream, try only once
    let (mut s, r) = connection.open_bi().await.anyerr()?;
    tracing::info!("opened bidi stream to {}", remote_endpoint_id);
    // send the handshake unless we are using a custom alpn
    // when using a custom alpn, everything is up to the user
    if !args.common.is_custom_alpn() {
        // the connecting side must write first. we don't know if there will be something
        // on stdin, so just write a handshake.
        s.write_all(&dumbpipe::HANDSHAKE).await.anyerr()?;
    }
    if args.recv_only {
        tracing::info!(
            "forwarding stdout to {} (ignoring stdin)",
            remote_endpoint_id
        );
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s, None).await?;
    } else {
        tracing::info!("forwarding stdin/stdout to {}", remote_endpoint_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s, None).await?;
    }
    tokio::io::stdout().flush().await.anyerr()?;
    Ok(())
}

/// One iroh connection to the remote, shared by every forwarded TCP connection.
///
/// Dialing per TCP connection makes each one pay a full QUIC handshake, but the
/// real cost is what happens afterwards: every open connection keeps sending its
/// own keep-alive on every active path, so a browser that opens hundreds of
/// sockets leaves behind hundreds of independently chattering connections. QUIC
/// streams are cheap and share one connection's keep-alive and path state, so
/// hold a single connection and open a stream per TCP connection instead.
struct SharedConnection {
    endpoint: Endpoint,
    addr: EndpointAddr,
    alpn: Vec<u8>,
    /// The live connection, if there is one. Cleared and redialled whenever it
    /// is found to be closed, so a dropped link recovers on the next request
    /// rather than wedging the proxy.
    current: tokio::sync::Mutex<Option<Connection>>,
}

impl SharedConnection {
    fn new(endpoint: Endpoint, addr: EndpointAddr, alpn: Vec<u8>) -> Self {
        Self {
            endpoint,
            addr,
            alpn,
            current: tokio::sync::Mutex::new(None),
        }
    }

    /// Returns the shared connection, dialing if there is not a live one.
    ///
    /// Callers that arrive while a dial is in flight queue on the mutex and then
    /// reuse its result, so a burst of TCP connections still produces one dial.
    async fn get(&self) -> Result<Connection> {
        let mut current = self.current.lock().await;
        if let Some(conn) = current.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            tracing::info!("shared connection to {} closed, redialing", self.addr.id);
        }
        let conn = self
            .endpoint
            .connect(self.addr.clone(), &self.alpn)
            .await
            .std_context(format!("error connecting to {}", self.addr.id))?;
        tracing::info!("opened shared connection to {}", self.addr.id);
        *current = Some(conn.clone());
        Ok(conn)
    }

    /// Open a stream on the shared connection.
    async fn open_bi(&self) -> Result<(noq::SendStream, noq::RecvStream)> {
        // The connection can die between being handed out and being used, so try
        // twice: the second `get` observes the closed connection and redials.
        let mut last_err = None;
        for _ in 0..2 {
            let conn = self.get().await?;
            match conn.open_bi().await {
                Ok(pair) => return Ok(pair),
                Err(cause) => {
                    tracing::debug!("error opening stream, will retry: {}", cause);
                    last_err = Some(cause);
                }
            }
        }
        let cause = last_err.expect("loop runs at least once");
        Err(cause).std_context(format!("error opening stream to {}", self.addr.id))
    }
}

/// Listen on a tcp port and forward incoming connections to an endpoint.
async fn connect_tcp(args: ConnectTcpArgs) -> Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .std_context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .std_context("unable to bind endpoint")?;
    tracing::info!("tcp listening on {:?}", addrs);

    // Wait for our own endpoint to be ready before trying to connect.
    if (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }

    let tcp_listener = match tokio::net::TcpListener::bind(addrs.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", addrs, cause);
            return Ok(());
        }
    };
    async fn handle_tcp_accept(
        next: io::Result<(tokio::net::TcpStream, SocketAddr)>,
        connection: Arc<SharedConnection>,
        handshake: bool,
        idle_timeout: Option<Duration>,
    ) -> Result<()> {
        let (tcp_stream, tcp_addr) = next.std_context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let (mut endpoint_send, endpoint_recv) = connection.open_bi().await?;
        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, everything is up to the user
        if handshake {
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            endpoint_send
                .write_all(&dumbpipe::HANDSHAKE)
                .await
                .anyerr()?;
        }
        forward_bidi(tcp_recv, tcp_send, endpoint_recv, endpoint_send, idle_timeout).await?;
        Ok::<_, AnyError>(())
    }
    let addr = args.ticket.endpoint_addr();
    let connection = Arc::new(SharedConnection::new(
        endpoint,
        addr.clone(),
        args.common.alpn()?.to_vec(),
    ));
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let connection = Arc::clone(&connection);
        let handshake = !args.common.is_custom_alpn();
        let idle_timeout = args.common.idle_timeout();
        tokio::spawn(async move {
            if let Err(cause) = handle_tcp_accept(next, connection, handshake, idle_timeout).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Listen on an endpoint and forward incoming connections to a tcp socket.
async fn listen_tcp(args: ListenTcpArgs, do_socks: bool, input_config: Option<SocksForwardConfig>) -> Result<()> {


    let file_cfg = if let Some(cfg) = input_config {
        Some(cfg)
    } else {
        try_load_config_from_file()
    };

    // One resolver for the whole socks server, so every connection shares a
    // single warm DNS cache instead of resolving from scratch.
    let resolver = DnsResolver::new();

    if do_socks {
        let resolver = resolver.clone();
        tokio::spawn(async move {
            socks_server::spawn_socks_server(true, resolver).await.expect("Failed to start SOCKS5 server");
        });
    }


    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => bail_any!("invalid host string {}: {}", args.host, e),
    };
    let secret_key: SecretKey = match &file_cfg {
        Some(cfg) => {
            if let Some(sec) = cfg.iroh_secret.as_ref() {
                tracing::info!("Loaded secret key from file");
                SecretKey::from_str(sec.as_str())?
            } else {
                get_or_create_secret()?
            }
        },
        _ => get_or_create_secret()?
    };

    print_secret_key(&secret_key);

    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    if (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    let short = create_short_ticket(&addr);
    let ticket = EndpointTicket::new(addr);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!("Forwarding incoming requests to '{}'.", args.host);
    eprintln!("To connect, use e.g.:");
    eprintln!("dumbpipe connect-tcp {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect-tcp {short}");
    }
    tracing::info!("endpoint id is {}", ticket.endpoint_addr().id);
    tracing::info!(
        "relay url is {:?}",
        ticket
            .endpoint_addr()
            .relay_urls()
            .next()
            .map_or("None".to_string(), |url| url.to_string())
    );

    let seen_connections: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::new(Mutex::new(std::collections::HashMap::new()));

    setup_proxy_and_mothership(file_cfg, endpoint.clone(), short.to_string(), Arc::clone(&seen_connections)).await?;

    // forward one incoming stream to the tcp target
    async fn handle_stream(
        s: noq::SendStream,
        mut r: noq::RecvStream,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
        idle_timeout: Option<Duration>,
    ) -> Result<()> {
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.anyerr()?;
            ensure_any!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
        }
        let tcp_conn = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .std_context(format!("error connecting to {addrs:?}"))?;
        let (read, write) = tcp_conn.into_split();
        forward_bidi(read, write, r, s, idle_timeout).await
    }

    // handle a new incoming connection on the endpoint
    //
    // The connecting side multiplexes every forwarded TCP connection onto one
    // iroh connection, so keep accepting streams for as long as the connection
    // lives rather than handling a single stream and dropping it.
    async fn handle_endpoint_accept(
        accepting: Accepting,
        addrs: Vec<std::net::SocketAddr>,
        handshake: bool,
        endpoint: Endpoint,
        seen: Arc<Mutex<std::collections::HashMap<String, String>>>,
        idle_timeout: Option<Duration>,
    ) -> Result<()> {
        let iroh_conn = accepting.await.std_context("error accepting connection")?;
        let remote_endpoint_id = iroh_conn.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let conn_type = if let Some(info) = endpoint.remote_info(remote_endpoint_id).await {
            let is_direct = info.addrs().any(|a| {
                matches!(a.addr(), TransportAddr::Ip(_))
                    && matches!(a.usage(), TransportAddrUsage::Active)
            });
            if is_direct { "direct" } else { "relay" }
        } else {
            "relay"
        };
        seen.lock().unwrap().insert(remote_endpoint_id.to_string(), conn_type.to_string());

        loop {
            // `accept_bi` resolves with a connection error when the peer goes
            // away, which is the normal way out of this loop.
            let (s, r) = match iroh_conn.accept_bi().await {
                Ok(pair) => pair,
                Err(cause) => {
                    tracing::info!("connection from {} ended: {}", remote_endpoint_id, cause);
                    return Ok(());
                }
            };
            tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
            let addrs = addrs.clone();
            tokio::spawn(async move {
                if let Err(cause) = handle_stream(s, r, addrs, handshake, idle_timeout).await {
                    tracing::warn!("error handling stream: {}", cause);
                }
            });
        }
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
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
        let seen = Arc::clone(&seen_connections);
        let ep = endpoint.clone();
        let idle_timeout = args.common.idle_timeout();
        tokio::spawn(async move {
            if let Err(cause) =
                handle_endpoint_accept(connecting, addrs, handshake, ep, seen, idle_timeout).await
            {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

async fn setup_proxy_and_mothership(file_cfg: Option<SocksForwardConfig>, _endpoint: Endpoint, ticket: String, seen_connections: Arc<Mutex<std::collections::HashMap<String, String>>>) -> Result<()> {

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
                tracing::error!("PROXY_NAME is required with mothership");
                exit(1)
            }
        };
        tracing::info!("Proxy name: {name}");
        tracing::info!("Will check in with mothership at {}, interval: {}", &mothership, checkin_internval);
        let conns_clone = Arc::clone(&seen_connections);
        tokio::spawn( async move {
            let client = reqwest::Client::new();
            loop {
                let snapshot: std::collections::HashMap<String, String> = conns_clone.lock().unwrap().clone();
                let mut map = Map::new();
                for (id, conn_type) in &snapshot {
                    map.insert(id.clone(), Value::String(conn_type.clone()));
                }
                let obj = Value::Object(map);

                let params = [("name", name.as_str()), ("ticket", &ticket), ("connections", &obj.to_string())];
                tracing::info!("connection data: {}", &obj.to_string());

                let res = client.post(&mothership)
                    .form(&params)
                    .send()
                    .await;

                match res {
                    Ok(res) => {
                        match res.status() {
                            StatusCode::OK => {
                                tracing::info!("Checked in with mothership");
                                conns_clone.lock().unwrap().retain(|k, _| !snapshot.contains_key(k));
                                let x = res.text().await;
                                if let Ok(x) = x {
                                    tracing::info!("result is {x}")
                                }

                            },
                            StatusCode::GONE => {
                                tracing::error!("Mothership sent status 410: Gone, shutting down");
                                exit(1)
                            },
                            status_code => {
                                let res = res.text().await.unwrap_or(String::from("unknown"));
                                tracing::error!("Check in failed, will retry. Got status code {status_code}: {res}");
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Could not connect to mothership {:?}", e)
                    }
                }

                sleep(Duration::from_secs(checkin_internval)).await;
            }
        });
    } else {
        tracing::warn!("No mothership supplied");
    };
    Ok(())
}

/// Creates a ticket that only includes the id and any relay urls
fn create_short_ticket(addr: &EndpointAddr) -> EndpointTicket {
    let mut short = EndpointAddr::new(addr.id);
    for relay_url in addr.relay_urls() {
        short = short.with_relay_url(relay_url.clone());
    }
    short.into()
}

#[cfg(unix)]
/// Listen on an endpoint and forward incoming connections to a Unix socket.
async fn listen_unix(args: ListenUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![args.common.alpn()?]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    if (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    let short = create_short_ticket(&addr);
    let ticket = EndpointTicket::new(addr);

    // print the ticket on stderr so it doesn't interfere with the data itself
    //
    // note that the tests rely on the ticket being the last thing printed
    eprintln!(
        "Forwarding incoming requests to '{}'.",
        socket_path.display()
    );
    eprintln!("To connect, use e.g.:");
    eprintln!("dumbpipe connect-unix --socket-path /path/to/client.sock {ticket}");
    eprintln!("dumbpipe connect-tcp --addr 127.0.0.1:8080 {ticket}");
    if args.common.verbose > 0 {
        eprintln!("or:\ndumbpipe connect-unix --socket-path /path/to/client.sock {short}");
        eprintln!("dumbpipe connect-tcp --addr 127.0.0.1:8080 {short}");
    }
    tracing::info!("endpoint id is {}", ticket.endpoint_addr().id);
    tracing::info!(
        "relay url is {:?}",
        ticket
            .endpoint_addr()
            .relay_urls()
            .next()
            .map_or("None".to_string(), |url| url.to_string())
    );

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        accepting: Accepting,
        socket_path: PathBuf,
        handshake: bool,
    ) -> Result<()> {
        tracing::trace!("accepting connection");
        let connection = accepting.await.std_context("error accepting connection")?;
        let remote_endpoint_id = &connection.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .std_context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
        if handshake {
            // read the handshake and verify it
            tracing::trace!("reading handshake");
            let mut buf = [0u8; dumbpipe::HANDSHAKE.len()];
            r.read_exact(&mut buf).await.anyerr()?;
            ensure_any!(buf == dumbpipe::HANDSHAKE, "invalid handshake");
            tracing::trace!("handshake verified");
        }
        tracing::trace!("connecting to backend socket {:?}", socket_path);
        let connection = UnixStream::connect(&socket_path)
            .await
            .std_context(format!("error connecting to {socket_path:?}"))?;
        tracing::trace!("connected to backend socket");
        let (read, write) = connection.into_split();
        tracing::trace!("starting forward_bidi");
        forward_bidi(read, write, r, s, None).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let socket_path = socket_path.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(connecting, socket_path, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
/// A RAII guard to clean up a Unix socket file.
struct UnixSocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("failed to remove socket file {:?}: {}", self.path, e);
            }
        }
    }
}

#[cfg(unix)]
/// Listen on a Unix socket and forward connections to an endpoint.
async fn connect_unix(args: ConnectUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .std_context("unable to bind endpoint")?;
    tracing::info!("unix listening on {:?}", socket_path);

    // Wait for our own endpoint to be ready before trying to connect.
    if (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }

    // Remove existing socket file if it exists
    if let Err(e) = tokio::fs::remove_file(&socket_path).await {
        if e.kind() != io::ErrorKind::NotFound {
            bail_any!("failed to remove existing socket file: {}", e);
        }
    }

    let addr = args.ticket.endpoint_addr();
    tracing::info!("connecting to remote endpoint: {:?}", addr);
    let connection = endpoint
        .connect(addr.clone(), &args.common.alpn()?)
        .await
        .std_context("failed to connect to remote endpoint")?;
    tracing::info!("connected to remote endpoint successfully");

    let unix_listener = UnixListener::bind(&socket_path)
        .with_std_context(|_| format!("failed to bind Unix socket at {socket_path:?}"))?;
    tracing::info!("bound local unix socket: {:?}", socket_path);

    let _guard = UnixSocketGuard {
        path: socket_path.clone(),
    };

    async fn handle_unix_accept(
        next: io::Result<(UnixStream, tokio::net::unix::SocketAddr)>,
        connection: iroh::endpoint::Connection,
        handshake: bool,
    ) -> Result<()> {
        tracing::trace!("handling new local connection");
        let (unix_stream, unix_addr) = next.std_context("error accepting unix connection")?;
        let (unix_recv, unix_send) = unix_stream.into_split();
        tracing::trace!("got unix connection from {:?}", unix_addr);

        tracing::trace!("opening bidi stream");
        let (mut endpoint_send, endpoint_recv) = connection
            .open_bi()
            .await
            .std_context("error opening bidi stream")?;
        tracing::trace!("bidi stream opened");

        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, everything is up to the user
        if handshake {
            tracing::trace!("sending handshake");
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            endpoint_send
                .write_all(&dumbpipe::HANDSHAKE)
                .await
                .anyerr()?;
            tracing::trace!("handshake sent");
        }

        tracing::trace!("starting forward_bidi");
        forward_bidi(unix_recv, unix_send, endpoint_recv, endpoint_send, None).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    tracing::info!("entering accept loop");
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = unix_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        tracing::trace!("accepted a local connection");
        let connection = connection.clone();
        let handshake = !args.common.is_custom_alpn();
        tokio::spawn(async move {
            tracing::trace!("spawning handler task");
            if let Err(cause) = handle_unix_accept(next, connection, handshake).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
            tracing::trace!("handler task finished");
        });
    }

    Ok(())
}

async fn generate_ticket() -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let public_key = secret_key.public();
    let addr = EndpointAddr::new(public_key);
    let ticket = EndpointTicket::new(addr);
    println!("{}", ticket);
    Ok(())
}


async fn check_auto_shutdown(options: &CommonArgs) {
    if let Some(secs) = options.auto_shutdown {
        tracing::info!("Will automatically shutdown in {} seconds", secs);
        tokio::spawn(async move {
            sleep(Duration::from_secs(secs as u64)).await;
            tracing::info!("Auto shutdown happening NOW");
            exit(0);
        });
    }
}

pub fn print_secret_key(key: &SecretKey) {
    let bytes = key.to_bytes();
    let strrep = &HEXLOWER.encode(
        &bytes
    );
    tracing::info!("Secret key: {}", strrep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Regression test for the descriptor leak: a forwarding direction that ends
    /// must leave the destination socket readable-to-EOF by its peer.
    ///
    /// Without the shutdown in `copy_and_shutdown` the peer's `read_to_end` never
    /// returns, the connection stays half-open forever, and its descriptor is
    /// pinned for the lifetime of the process.
    #[tokio::test]
    async fn copy_and_shutdown_closes_write_side() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let peer = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            // only returns once the other end has actually shut its write side down
            sock.read_to_end(&mut got).await.unwrap();
            got
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let (_read, mut write) = sock.into_split();
        let mut src = &b"hello"[..];
        let n = copy_and_shutdown(&mut src, &mut write, &Activity::new())
            .await
            .unwrap();
        assert_eq!(n, 5);

        // hold the write half open past the copy, so passing can only be the
        // explicit shutdown and never `OwnedWriteHalf`'s shutdown-on-drop
        let got = timeout(Duration::from_secs(5), peer)
            .await
            .expect("peer never saw EOF: write side was not shut down")
            .unwrap();
        assert_eq!(got, b"hello");
        drop(write);
    }

    /// The idle watchdog reads its verdict from `Activity`, so the accounting
    /// has to survive a quiet stretch and be reset by traffic.
    #[tokio::test]
    async fn activity_tracks_idle_time() {
        let activity = Activity::new();
        assert!(activity.idle_for() < Duration::from_millis(100));

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            activity.idle_for() >= Duration::from_millis(200),
            "idle time should grow while nothing moves"
        );

        activity.touch();
        assert!(
            activity.idle_for() < Duration::from_millis(100),
            "traffic should reset the idle clock"
        );
    }

    /// `copy_tracking` replaced `tokio::io::copy`, so it has to copy faithfully
    /// and report the progress the watchdog depends on.
    #[tokio::test]
    async fn copy_tracking_copies_and_records() {
        let activity = Activity::new();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let before = activity.idle_for();
        assert!(before >= Duration::from_millis(100));

        let payload = vec![7u8; COPY_BUF_SIZE * 2 + 13];
        let mut src = &payload[..];
        let mut dst: Vec<u8> = Vec::new();
        let n = copy_tracking(&mut src, &mut dst, &activity).await.unwrap();

        assert_eq!(n as usize, payload.len());
        assert_eq!(dst, payload, "payload must survive a multi-buffer copy");
        assert!(
            activity.idle_for() < before,
            "copying must reset the idle clock"
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();
    raise_nofile_limit();
    let args = Args::try_parse();
    if let Ok(args) = args {
        let res = match args.command {
            Commands::GenerateTicket => generate_ticket().await,
            Commands::Listen(args) => listen_stdio(args).await,
            Commands::ListenTcp(args) => {
                check_auto_shutdown(&args.common).await;
                listen_tcp(args, false, None).await
            },
            Commands::SocksServerForward(args) => {
                check_auto_shutdown(&args.common).await;
                let listen_args = ListenTcpArgs { host: String::from(SOCKS_LISTEN_ADDR), common: args.common, ticket_out_path: args.ticket_out_path };
                listen_tcp(listen_args, true, None).await
            },
            Commands::Connect(args) => connect_stdio(args).await,
            Commands::ConnectTcp(args) => connect_tcp(args).await,

            #[cfg(unix)]
            Commands::ListenUnix(args) => listen_unix(args).await,

            #[cfg(unix)]
            Commands::ConnectUnix(args) => connect_unix(args).await,

            Commands::SocksOnly(_args) => Ok({
                socks_server::spawn_socks_server(false, DnsResolver::new()).await.anyerr()?
            }),
            Commands::GenSecret(_) => {
                let key = SecretKey::generate();
                print_secret_key(&key);
                exit(0)
            }
        };
        match res {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1)
            }
        }
    } else {
        // no default command
        tracing::info!("No command supplied, operating in socks server forward mode");
        // no command was specified in the arguments, run the server socks command
        let listen_args = ListenTcpArgs { host: String::from(SOCKS_LISTEN_ADDR), ticket_out_path: None, common: CommonArgs {
            ipv4_addr: None,
            ipv6_addr: None,
            custom_alpn: None,
            verbose: 0,
            auto_shutdown: None,
            idle_timeout: DEFAULT_IDLE_TIMEOUT_SECS,
        } };
        listen_tcp(listen_args, true, None).await.expect("listen failed")
    };
    tracing::info!("Dumbpipe exiting");
    Ok(())
}
