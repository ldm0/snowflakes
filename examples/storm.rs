use anyhow::{Context as AnyhowContext, Result};
use bytes::BytesMut;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use snowflakes::WinterFramed;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream},
};

const PATTERN: &str = "Noise_N_25519_AESGCM_SHA256";

#[derive(Parser)]
struct Cli {
    /// Generate key pair.
    #[clap(long)]
    generate: bool,
    /// Server mode.
    #[clap(long)]
    server: bool,
}

async fn client() -> Result<()> {
    let builder = snow::Builder::new(PATTERN.parse()?);
    let public = fs::read("target/public_key").await?;
    let handshake = builder.remote_public_key(&public).build_initiator()?;
    let stream = TcpStream::connect("127.0.0.1:7333")
        .await
        .context("Connect failed.")?;
    stream.set_nodelay(true).context("Set no delay failed.")?;

    let mut winter_framed = WinterFramed::new(stream, handshake);
    winter_framed
        .send("test msg".into())
        .await
        .context("Send initial message failed.")?;

    let snow_framed = winter_framed.into_snow_framed()?;
    let mut snow_flakes = snow_framed.into_snow_flakes(1 << 20);

    loop {
        let message = match BufReader::new(io::stdin()).lines().next_line().await {
            Ok(Some(x)) => x,
            _ => break,
        };
        let bytes: BytesMut = message.as_bytes().into();
        snow_flakes
            .send(bytes.freeze())
            .await
            .context("Send message failed.")?;
    }
    Ok(())
}

async fn server() -> Result<()> {
    let builder = snow::Builder::new(PATTERN.parse()?);
    let private_key = fs::read("target/private_key").await?;
    let handshake = builder.local_private_key(&private_key).build_responder()?;
    let listener = TcpListener::bind("127.0.0.1:7333")
        .await
        .context("Client listen error.")?;
    let (stream, _) = listener.accept().await?;
    let mut winter_framed = WinterFramed::new(stream, handshake);

    let msg = winter_framed
        .next()
        .await
        .context("Read initial message failed.")?
        .context("Parse initial message failed")?;

    dbg!(msg);

    let snow_framed = winter_framed.into_snow_framed()?;
    let mut snow_flakes = snow_framed.into_snow_flakes(1 << 20);

    loop {
        let msg = match snow_flakes.next().await {
            Some(x) => x.context("Get next msg failed")?,
            None => break,
        };
        let x = String::from_utf8_lossy(msg.as_ref()).into_owned();
        println!("Client said: {}", x);
    }
    Ok(())
}

async fn generate() -> Result<()> {
    let builder = snow::Builder::new(PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    fs::write("target/private_key", keypair.private).await?;
    fs::write("target/public_key", keypair.public).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.generate {
        generate().await?;
    } else if cli.server {
        server().await?;
    } else {
        client().await?;
    }

    Ok(())
}
