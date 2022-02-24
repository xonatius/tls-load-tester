use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net;

static CIPHER_SUITES: [u8; 40] = [
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
    0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x00, 0x3c, // TLS_RSA_WITH_AES_128_CBC_SHA256
    0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x00, 0x04, // TLS_RSA_WITH_RC4_128_MD5
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
        + CIPHER_SUITES.len() /* Cipher Suites */
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
    b.put_u16(CIPHER_SUITES.len() as u16); // Cipher Suites Length
    b.put_slice(&CIPHER_SUITES);
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = net::TcpStream::connect("example.com:443").await?;
    stream
        .write_all(&format_client_hello("example.com"))
        .await?;

    let mut buf = BytesMut::new();
    loop {
        let len = stream.read_buf(&mut buf).await?;
        if len == 0 {
            return Ok(());
        }
    }
}