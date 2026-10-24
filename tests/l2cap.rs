// SPDX-License-Identifier: GPL-3.0-or-later

//! Checks for the CTAP 2.3 BLE data channel.
//!
//! `l2cap_connect_failure_falls_back_to_websocket` runs anywhere: the L2CAP
//! connect is pointed at an address that never answers, so the flow must fall
//! back to the WebSocket channel and still complete.
//!
//! The other two form a pair and need two devices, because an LE controller
//! cannot open a connection to its own address (which is why the old
//! self-loopback test here could never pass). On the phone stand-in (any
//! Linux box with an LE adapter):
//!
//! ```sh
//! cargo test --features l2cap --test l2cap mock_phone -- --ignored --nocapture
//! ```
//!
//! It prints a `UCABLED_L2CAP_PEER` value; on the desktop side:
//!
//! ```sh
//! UCABLED_L2CAP_PEER=<addr>:<psm> cargo test --features l2cap --test l2cap \
//!     desktop_flow_over_l2cap -- --ignored
//! ```
#![cfg(feature = "l2cap")]

mod common;

use anyhow::Result;
use bluer::l2cap::{SeqPacket, SeqPacketListener, SocketAddr};
use bluer::{Address, AddressType};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use common::run_relay;
use ucabled::phone::{self, CableLink, CableTransport, MSG_CTAP, MSG_SHUTDOWN};
use ucabled::qr::{self, RequestType};
use ucabled::session::{Channel, DesktopFlow};

/// Fixed keys so the two-device tests derive the same PSK and identity on
/// both sides (this is test-only material, never used by the real daemon).
const DESKTOP_IDENTITY: [u8; 32] = [0x2a; 32];
const QR_SECRET: [u8; 16] = [0x11; 16];
const PLAINTEXT_EID: [u8; 16] = [0x22; 16];

fn desktop_identity() -> SecretKey {
    SecretKey::from_slice(&DESKTOP_IDENTITY).expect("fixed test key is a valid scalar")
}

fn desktop_identity_x962_uncompressed() -> Vec<u8> {
    desktop_identity()
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn test_psk() -> [u8; 32] {
    let mut psk = [0u8; 32];
    ucabled::kdf::derive(
        &QR_SECRET,
        &PLAINTEXT_EID,
        ucabled::kdf::Purpose::Psk,
        &mut psk,
    );
    psk
}

/// Play the phone over an accepted L2CAP channel: answer the Noise handshake,
/// send a post-handshake message, answer CTAP commands until shutdown.
async fn serve_phone(stream: SeqPacket, psk: &[u8; 32], peer_identity: &[u8]) -> Result<()> {
    let initial = ucabled::l2cap::recv(&stream).await?;
    let (response, crypter, handshake_hash) =
        ucabled::handshake::respond_qr(psk, peer_identity, &initial)
            .ok_or_else(|| anyhow::anyhow!("handshake failed"))?;
    ucabled::l2cap::send(&stream, &response).await?;
    let mut link = CableLink {
        transport: CableTransport::L2cap(stream),
        crypter,
        handshake_hash,
    };
    // Post-handshake message; contents are not inspected by the desktop.
    let post = vec![0xa1, 0x01, 0x40];
    let ct = link
        .crypter
        .encrypt(&post)
        .ok_or_else(|| anyhow::anyhow!("encrypt failed"))?;
    link.transport.send(ct).await?;
    loop {
        match link.recv_message().await {
            Ok((MSG_CTAP, _)) => link.send_ctap(&[0x00, 0xa1, 0x01, 0x40]).await?,
            Ok((MSG_SHUTDOWN, _)) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

/// A phone that picked the BLE channel is unreachable on the L2CAP PSM (stale
/// address, radio trouble); the flow must fall back to the WebSocket channel
/// and still complete the transaction.
#[tokio::test]
async fn l2cap_connect_failure_falls_back_to_websocket() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base = format!("ws://{addr}");
    tokio::spawn(run_relay(listener));

    let identity = SecretKey::random(&mut OsRng);
    let compressed = identity.public_key().to_encoded_point(true);
    let compressed: &[u8; 33] = compressed.as_bytes().try_into().unwrap();
    let mut qr_secret = [0u8; 16];
    OsRng.fill_bytes(&mut qr_secret);

    let qr_url = qr::encode_qr_url(
        compressed,
        &qr_secret,
        2,
        false,
        RequestType::GetAssertion,
        &[qr::TRANSPORT_WEBSOCKET, qr::TRANSPORT_BLE],
    );
    let parsed = qr::parse_qr_url(&qr_url).unwrap();
    let peer_public = p256::PublicKey::from_sec1_bytes(&parsed.compressed_public_key).unwrap();
    let peer_identity = peer_public.to_encoded_point(false).as_bytes().to_vec();

    let (eid_tx, eid_rx) = oneshot::channel::<[u8; 16]>();
    let phone_base = base.clone();
    let phone_task = tokio::spawn(async move {
        let r = async {
            let (outcome, ws, psk) = phone::phone_setup(&phone_base, &parsed.secret, None).await?;
            eid_tx
                .send(outcome.plaintext_eid)
                .map_err(|_| anyhow::anyhow!("eid send"))?;
            let getinfo_reply = vec![0xa1, 0x01, 0x41, 0x00];
            phone::phone_run(ws, &psk, &peer_identity, &getinfo_reply).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = &r {
            eprintln!("phone task failed: {e:#}");
        }
        r
    });

    let plaintext_eid = eid_rx.await?;
    let flow = DesktopFlow {
        tunnel_base: Some(base),
        // Nothing listens at this address; with an adapter present the
        // connect stalls until the connect timeout, without one it fails
        // immediately. Either way the flow must end up on the WebSocket.
        channel: Channel::L2cap {
            address: Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            address_type: AddressType::LePublic,
            psm: 0x89,
        },
        qr_secret,
        identity,
        plaintext_eid,
        handshake_timeout: ucabled::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: std::time::Duration::from_millis(500),
    };

    let start = std::time::Instant::now();
    let result = flow.run(&[0x04]).await?;
    let elapsed = start.elapsed();
    phone_task.await??;

    assert_eq!(result.ctap_reply[0], 0x00, "expected CTAP success status");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the fallback must be prompt, not a host-level timeout: {elapsed:?}"
    );
    Ok(())
}

/// Desktop role of the two-device check: run the full flow over the BLE
/// channel against a `mock_phone` running elsewhere.
#[tokio::test]
#[ignore = "needs a second device running mock_phone (see module docs)"]
async fn desktop_flow_over_l2cap() -> Result<()> {
    let peer = std::env::var("UCABLED_L2CAP_PEER")
        .expect("set UCABLED_L2CAP_PEER=<addr>:<psm> as printed by mock_phone");
    let (addr, psm) = peer
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("UCABLED_L2CAP_PEER must be <addr>:<psm>"))?;
    let address: Address = addr.parse()?;
    let psm = u16::from_str_radix(psm.trim_start_matches("0x"), 16)?;

    let flow = DesktopFlow {
        tunnel_base: None,
        channel: Channel::L2cap {
            address,
            // The mock phone is a Linux adapter; a real phone would use a
            // random address instead.
            address_type: AddressType::LePublic,
            psm,
        },
        qr_secret: QR_SECRET,
        identity: desktop_identity(),
        plaintext_eid: PLAINTEXT_EID,
        handshake_timeout: ucabled::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: ucabled::tunnel::DIAL_TIMEOUT,
    };
    let result = flow.run(&[0x04]).await?;

    assert_eq!(result.ctap_reply[0], 0x00, "expected CTAP success status");
    assert!(!result.post_handshake.is_empty());
    Ok(())
}

/// Phone role of the two-device check: listen on an L2CAP CoC, print how to
/// reach it, and serve exactly one transaction.
#[tokio::test]
#[ignore = "second-device role; run with --nocapture to see the PSM"]
async fn mock_phone() -> Result<()> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let listener = SeqPacketListener::bind(SocketAddr::any_le()).await?;
    let psm = listener.as_ref().local_addr()?.psm;
    eprintln!(
        "mock phone listening; run the other side with:\n  UCABLED_L2CAP_PEER={}:0x{psm:02x}",
        adapter.address().await?
    );

    let (stream, _) = listener.accept().await?;
    let psk = test_psk();
    let peer_identity = desktop_identity_x962_uncompressed();
    serve_phone(stream, &psk, &peer_identity).await
}
