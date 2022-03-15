use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, Result};
use rand::Rng;
use tokio::io::{stdout, AsyncReadExt, AsyncWriteExt};
use tokio::net;
use tokio::time::{sleep, timeout};

static ATTEMPT_COUNT: AtomicUsize = AtomicUsize::new(0);
static ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);
static CONNECTED_COUNT: AtomicUsize = AtomicUsize::new(0);
static SENT_COUNT: AtomicUsize = AtomicUsize::new(0);
static RECV_COUNT: AtomicUsize = AtomicUsize::new(0);
static TIMEOUT_COUNT: AtomicUsize = AtomicUsize::new(0);

static CIPHER_SUITES: [u8; 26] = [
    0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x24, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    0xc0, 0x28, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    0xc0, 0x0a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc0, 0x23, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    0xc0, 0x27, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xc0, 0x09, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
];

static CIPHER_SUITES_RSA_ONLY: [u8; 14] = [
    0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x28, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc0, 0x27, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
];

static SIGNATURE_ALGORITHMS_EXT: [u8; 26] = [
    0x00, 0x0d, // Type
    0x00, 0x16, // Length
    0x00, 0x14, // Signature Hash Algorithm Length
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x01, // rsa_pkcs1_sha384
    0x06, 0x01, // rsa_pkcs1_sha512
    0x03, 0x01, // SHA224 RSA
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x06, 0x03, // ecdsa_secp521r1_sha512
    0x03, 0x03, // SHA224 ECDSA
    0x02, 0x01, // rsa_pkcs1_sha1
    0x02, 0x03, // ecdsa_sha1
];

static STATUS_REQUEST_EXT: [u8; 9] = [
    0x00, 0x05, // Type
    0x00, 0x05, // Length
    0x01, // Type: OCSP
    0x00, 0x00, // ID list length
    0x00, 0x00, // Extensions list length
];

static SESSION_TICKETS_EXT: [u8; 4] = [
    0x00, 0x23, // Type
    0x00, 0x00, // Length
];

static SUPPORTED_GROUPS_EXT: [u8; 10] = [
    0x00, 0x0a, // Type
    0x00, 0x06, // Length
    0x00, 0x04, // List Lenght
    0x00, 0x17, // secp256r1
    0x00, 0x18, // secp384r1
];

static EC_POINT_FORMATS_EXT: [u8; 6] = [
    0x00, 0x0b, // Type
    0x00, 0x02, // Length
    0x01, 0x00, // Uncompressed
];

static TRANSPARENCY_INFO_EXT: [u8; 4] = [
    0x00, 0x12, // Type
    0x00, 0x00, // Length
];

/// Generates ClientHello Record
fn format_client_hello(sni: &str) -> Bytes {
    let mut sni_ext = BytesMut::new();
    sni_ext.put_u16(0);
    sni_ext.put_u16(5 + sni.len() as u16);
    sni_ext.put_u16(3 + sni.len() as u16);
    sni_ext.put_u8(0);
    sni_ext.put_u16(sni.len() as u16);
    sni_ext.put_slice(sni.as_bytes());
    let sni_ext = sni_ext.freeze();

    let extensions = [
        Bytes::from(SIGNATURE_ALGORITHMS_EXT.as_ref()),
        sni_ext,
        Bytes::from(STATUS_REQUEST_EXT.as_ref()),
        Bytes::from(SESSION_TICKETS_EXT.as_ref()),
        Bytes::from(SUPPORTED_GROUPS_EXT.as_ref()),
        Bytes::from(EC_POINT_FORMATS_EXT.as_ref()),
        Bytes::from(TRANSPARENCY_INFO_EXT.as_ref()),
    ];

    let extension_length: usize = extensions.iter().map(Bytes::len).sum();

    let client_hello_length: usize = extension_length /* Extensions */
        + 2 /* Extensions length */
        + 2 /* Compressions + length */
        + CIPHER_SUITES_RSA_ONLY.len() /* Cipher Suites */
        + 2 /* Cipher quites length */
        + 32 /* Session id */
        + 1 /* Session id length */
        + 32 /* Random */
        + 2 /* TLS version */;

    let tls_record_length = client_hello_length + 3 /* Length */ + 1 /* Type */;

    let mut b = BytesMut::with_capacity(1024);
    // TLS Record
    b.put_u8(22); // Record Type: Handshake
    b.put_u16(0x0301); // Version: TLS 1.0
    b.put_u16(tls_record_length.try_into().unwrap()); // Length
                                                      // Handshake Record
    b.put_u8(1); // Type: Client Hello
    b.put_u8(0); // Length
    b.put_u16(client_hello_length.try_into().unwrap());
    b.put_u16(0x0303); // Version: TLS1.2
    b.put_slice(&rand::thread_rng().gen::<[u8; 32]>()); // Random
    b.put_u8(32); // Session ID length
    b.put_slice(&rand::thread_rng().gen::<[u8; 32]>()); // Session ID
    b.put_u16(CIPHER_SUITES_RSA_ONLY.len() as u16); // Cipher Suites Length
    b.put_slice(&CIPHER_SUITES_RSA_ONLY);
    b.put_u8(1); // Compression Methods Length
    b.put_u8(0); // Compression Methods: Null

    b.put_u16(extension_length.try_into().unwrap()); // Extensions Length
    extensions.iter().for_each(|x| b.put_slice(x));

    assert!(
        b.len() == tls_record_length + 5,
        "Expected {}, got {}...",
        tls_record_length + 5,
        b.len()
    );

    b.into()
}

#[derive(Debug)]
enum HandshakeRecord {
    Buffer(BytesMut),
    Skip(usize),
}

#[derive(Debug)]
enum TlsRecord {
    Buffer(BytesMut),
    Handshake(usize),
    Skip(usize),
}

async fn loop_ch(addr: SocketAddr, sni: &str) {
    loop {
        let _ = run_once(addr, sni).await;
    }
}

async fn socket_rw_loop(stream: &mut net::TcpStream) {
    let mut record = TlsRecord::Buffer(BytesMut::with_capacity(5));
    let mut handshake = HandshakeRecord::Buffer(BytesMut::with_capacity(4));
    let mut buf = BytesMut::with_capacity(8 * 1024);
    loop {
        let mut len = if let Ok(len) = stream.read_buf(&mut buf).await {
            len
        } else {
            return;
        };
        if len == 0 {
            return;
        }
        while len > 0 {
            //println!("len={len}, record={record:?} handshake={handshake:?}");
            match record {
                TlsRecord::Buffer(mut record_buf) => {
                    let size = std::cmp::min(5 - record_buf.len(), len);
                    if size == 0 {
                        return;
                    }
                    record_buf.put_slice(&buf[..size]);
                    buf.advance(size);
                    len -= size;
                    if record_buf.len() == 5 {
                        let content_type = record_buf[0];
                        let expect =
                            u16::from_be_bytes(record_buf[3..5].try_into().expect("Fixed size"))
                                .into();
                        record = if content_type == 22 {
                            TlsRecord::Handshake(expect)
                        } else {
                            TlsRecord::Skip(expect)
                        };
                    } else {
                        record = TlsRecord::Buffer(record_buf);
                    }
                }
                TlsRecord::Handshake(expect) => {
                    if expect == 0 {
                        record = TlsRecord::Buffer(BytesMut::with_capacity(5));
                        continue;
                    };
                    let mut len2 = std::cmp::min(expect, len);
                    len -= len2;
                    record = TlsRecord::Handshake(expect - len2);
                    while len2 > 0 {
                        match handshake {
                            HandshakeRecord::Buffer(mut handshake_buf) => {
                                let size = std::cmp::min(4 - handshake_buf.len(), len2);
                                if size == 0 {
                                    return;
                                }
                                handshake_buf.put_slice(&buf[..size]);
                                len2 -= size;
                                buf.advance(size);
                                if handshake_buf.len() == 4 {
                                    let handshake_type = handshake_buf[0];
                                    if handshake_type == 12 {
                                        return;
                                    }
                                    handshake_buf[0] = 0;
                                    let expect = u32::from_be_bytes(
                                        handshake_buf[..4].try_into().expect("Fixed size"),
                                    ) as usize;
                                    handshake = HandshakeRecord::Skip(expect);
                                } else {
                                    handshake = HandshakeRecord::Buffer(handshake_buf);
                                }
                            }
                            HandshakeRecord::Skip(expect) => {
                                if expect <= len2 {
                                    handshake = HandshakeRecord::Buffer(BytesMut::with_capacity(4));
                                    len2 -= expect;
                                    buf.advance(expect);
                                } else {
                                    handshake = HandshakeRecord::Skip(expect - len2);
                                    buf.advance(len2);
                                    len2 = 0;
                                }
                            }
                        };
                    }
                }
                TlsRecord::Skip(expect) => {
                    if expect <= len {
                        len -= expect;
                        buf.advance(expect);
                        record = TlsRecord::Buffer(BytesMut::with_capacity(5));
                    } else {
                        record = TlsRecord::Skip(expect - len);
                        len = 0;
                    }
                }
            }
        }
    }
}

async fn run_once(addr: SocketAddr, sni: &str) -> Result<(), Box<dyn std::error::Error>> {
    ATTEMPT_COUNT.fetch_add(1, Ordering::SeqCst);
    let stream = net::TcpStream::connect(addr).await;
    if stream.is_err() {
        ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    let mut stream = stream?;
    CONNECTED_COUNT.fetch_add(1, Ordering::SeqCst);
    stream.write_all(&format_client_hello(sni)).await?;
    SENT_COUNT.fetch_add(1, Ordering::SeqCst);

    // RST instead of fin
    // TODO: Would be nice to forget about the socket, to keep the conneciton open on the peer
    stream.set_linger(Some(Duration::new(0, 0)))?;

    if let Ok(_) = timeout(Duration::from_secs(1), socket_rw_loop(&mut stream)).await {
        RECV_COUNT.fetch_add(1, Ordering::SeqCst);
    } else {
        TIMEOUT_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[clap()]
struct Args {
    #[clap(short, long)]
    address: String,
    #[clap(short, long)]
    sni: String,
    #[clap(short, long, default_value_t = 1)]
    concurrency: usize,
}

async fn stats_loop() -> Result<Box<dyn std::error::Error>> {
    let mut out = stdout();
    loop {
        let msg = format!(
            "\nAttempt: {}\nConnected: {}\nError: {}\nWritten: {}\nReceived: {}\nTimeout: {}\n",
            ATTEMPT_COUNT.load(Ordering::Relaxed),
            CONNECTED_COUNT.load(Ordering::Relaxed),
            ERROR_COUNT.load(Ordering::Relaxed),
            SENT_COUNT.load(Ordering::Relaxed),
            RECV_COUNT.load(Ordering::Relaxed),
            TIMEOUT_COUNT.load(Ordering::Relaxed),
        );
        out.write_all(msg.as_bytes()).await?;
        sleep(Duration::from_secs(10)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let addr: SocketAddr = args.address.parse().unwrap();

    let mut f = Vec::new();
    for _ in 0..args.concurrency {
        let addr = addr.clone();
        let sni = args.sni.clone();
        f.push(tokio::spawn(async move {
            loop_ch(addr, &sni).await;
        }));
    }

    let _stats = tokio::spawn(async move {
        let _ = stats_loop().await;
    });

    for i in f {
        let _ = i.await;
    }

    Ok(())
}
