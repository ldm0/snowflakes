use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use snowflakes::{SnowFlakes, WinterFramed};
use tokio::time::Instant;
use std::net::Ipv4Addr as addr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use rand::Rng;

const PATTERN: &str = "Noise_NK_25519_AESGCM_SHA256";

const FLAKE_SIZE: usize = 1 << 24;

async fn echo_server(port: u16, done: oneshot::Sender<()>, private_key: Vec<u8>) -> Result<()> {
    let listener = TcpListener::bind((addr::LOCALHOST, port)).await?;
    done.send(()).unwrap();
    let (stream, _addr) = listener.accept().await?;

    let handshake = snow::Builder::new(PATTERN.parse()?)
        .local_private_key(&private_key)
        .build_responder()?;
    let mut winter_framed = WinterFramed::new(stream, handshake);

    let msg = winter_framed
        .next()
        .await
        .context("Read initial message failed.")?
        .context("Parse initial message failed")?;
    assert!(msg.is_empty());
    winter_framed
        .send("".into())
        .await
        .context("Send initial message failed.")?;

    let mut snowflakes = winter_framed
        .into_snow_framed()?
        .into_snow_flakes(FLAKE_SIZE);

    loop {
        let msg = match snowflakes.next().await {
            Some(x) => x?,
            None => break,
        };
        snowflakes.send(msg.freeze()).await?;
    }
    Ok(())
}

async fn get_ready_client(port: u16, public_key: Vec<u8>) -> Result<SnowFlakes<TcpStream>> {
    let stream = TcpStream::connect((addr::LOCALHOST, port)).await?;
    let handshake = snow::Builder::new(PATTERN.parse()?)
        .remote_public_key(&public_key)
        .build_initiator()?;
    let mut winter_framed = WinterFramed::new(stream, handshake);
    winter_framed
        .send("".into())
        .await
        .context("Send initial message failed.")?;
    let msg = winter_framed
        .next()
        .await
        .context("Remote shutdown unexpectedly.")?
        .context("Get respond message failed.")?;
    assert_eq!(msg, "");
    Ok(winter_framed
        .into_snow_framed()?
        .into_snow_flakes(FLAKE_SIZE))
}

async fn client(port: u16, public_key: Vec<u8>) -> Result<()> {
    let mut snow_flakes = get_ready_client(port, public_key).await?;
    for _ in 0..100 {
        let number: u64 = rand::random();
        let mut bytes = BytesMut::new();
        bytes.put_slice(number.to_string().as_bytes());
        snow_flakes.send(bytes.freeze()).await.unwrap();
        let packet = snow_flakes
            .next()
            .await
            .context("Unexpected server shutdown")
            .unwrap()
            .context("Echo msg error")
            .unwrap();
        assert_eq!(packet, number.to_string().into_bytes());
    }
    Ok(())
}

async fn laggy_client(port: u16, public_key: Vec<u8>) -> Result<()> {
    let mut snow_flakes = get_ready_client(port, public_key).await?;
    let mut expected_nums = vec![];
    for _ in 0..100 {
        let number: u64 = rand::random();
        let mut bytes = BytesMut::new();
        bytes.put_slice(number.to_string().as_bytes());
        snow_flakes.send(bytes.freeze()).await?;
        expected_nums.push(number);
        if rand::random() {
            for number in expected_nums.drain(..) {
                let packet = snow_flakes
                    .next()
                    .await
                    .context("Unexpected server shutdown")?
                    .context("Echo msg error")?;
                assert_eq!(packet, number.to_string().into_bytes());
            }
        }
    }
    for number in expected_nums.into_iter() {
        let packet = snow_flakes
            .next()
            .await
            .context("Unexpected server shutdown")?
            .context("Echo msg error")?;
        assert_eq!(packet, number.to_string().into_bytes());
    }
    Ok(())
}

async fn strange_client(port: u16, public_key: Vec<u8>) -> Result<()> {
    let mut snow_flakes = get_ready_client(port, public_key).await?;
    let mut rng = rand::thread_rng();
    let random: Vec<u8> = (0..FLAKE_SIZE).map(|_| rng.gen::<u8>()).collect();
    for _ in 0..3 {
        snow_flakes.send(random.clone().into()).await.unwrap();
        assert_eq!(snow_flakes.next().await.unwrap().unwrap(), random);
    }

    let random: Vec<u8> = (0..65535).map(|_| rng.gen::<u8>()).collect();
    for _ in 0..100 {
        snow_flakes.send(random.clone().into()).await.unwrap();
        assert_eq!(snow_flakes.next().await.unwrap().unwrap(), random);
    }

    for i in 0..100 {
        let random: Vec<u8> = (0..(65535 - i)).map(|_| rng.gen::<u8>()).collect();
        snow_flakes.send(random.clone().into()).await.unwrap();
        assert_eq!(snow_flakes.next().await.unwrap().unwrap(), random);
    }

    for i in 0..100 {
        let random: Vec<u8> = (0..i).map(|_| rng.gen::<u8>()).collect();
        snow_flakes.send(random.clone().into()).await.unwrap();
        assert_eq!(snow_flakes.next().await.unwrap().unwrap(), random);
    }

    Ok(())
}

async fn bench_client(port: u16, public_key: Vec<u8>) -> Result<()> {
    let mut snow_flakes = get_ready_client(port, public_key).await?;
    let mut rng = rand::thread_rng();
    let random: Vec<u8> = (0..FLAKE_SIZE).map(|_| rng.gen::<u8>()).collect();
    println!("begins");
    let time = Instant::now();
    for _ in 0..100 {
        snow_flakes.send(random.clone().into()).await.unwrap();
        let byte = snow_flakes.next().await.unwrap().unwrap();
        assert_eq!(byte.len(), random.len());
        // println!("{}", time.elapsed().as_secs_f32());
    }
    let elapsed = time.elapsed();
    let time = elapsed.as_secs_f32();
    let total = random.len() * 100;
    println!("time: {}, size_bytes: {}, {}MB/s", time, total, total as f32 / time / 1024. / 1024.);
    Ok(())
}



fn generate() -> snow::Keypair {
    snow::Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap()
}

#[tokio::test]
async fn normal_echo() -> Result<()> {
    let port = rand::random();
    let (sender, receiver) = oneshot::channel();
    let snow::Keypair { public, private } = generate();
    let server_handle =
        tokio::spawn(async move { echo_server(port, sender, private).await.unwrap() });
    receiver.await?;
    client(port, public).await?;
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn laggy_echo() -> Result<()> {
    let port = rand::random();
    let (sender, receiver) = oneshot::channel();
    let snow::Keypair { public, private } = generate();
    let server_handle =
        tokio::spawn(async move { echo_server(port, sender, private).await.unwrap() });
    receiver.await?;
    laggy_client(port, public).await?;
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn strange_echo() -> Result<()> {
    let port = rand::random();
    let (sender, receiver) = oneshot::channel();
    let snow::Keypair { public, private } = generate();
    let server_handle =
        tokio::spawn(async move { echo_server(port, sender, private).await.unwrap() });
    receiver.await?;
    strange_client(port, public).await?;
    server_handle.await?;
    Ok(())
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark() -> Result<()> {
    let port = rand::random();
    let (sender, receiver) = oneshot::channel();
    let snow::Keypair { public, private } = generate();
    let server_handle =
        tokio::spawn(async move { echo_server(port, sender, private).await.unwrap() });
    receiver.await?;
    bench_client(port, public).await?;
    server_handle.await?;
    Ok(())
}
