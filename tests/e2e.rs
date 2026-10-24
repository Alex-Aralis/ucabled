// SPDX-License-Identifier: GPL-3.0-or-later

mod common;

use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use anyhow::Result;
use common::run_relay;
use ucabled::error::TransactionError;
use ucabled::phone;
use ucabled::qr::{self, RequestType};
use ucabled::session::DesktopFlow;

#[tokio::test]
async fn full_roundtrip_over_local_relay() -> Result<()> {
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
        &[qr::TRANSPORT_WEBSOCKET],
    );
    let parsed = qr::parse_qr_url(&qr_url).unwrap();
    assert_eq!(&parsed.compressed_public_key, compressed);
    assert_eq!(parsed.secret, qr_secret);

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
        channel: ucabled::session::Channel::Websocket,
        qr_secret,
        identity,
        plaintext_eid,
        handshake_timeout: ucabled::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: ucabled::tunnel::DIAL_TIMEOUT,
    };
    let result = flow.run(&[0x04]).await?;

    phone_task.await??;

    assert_eq!(result.ctap_reply[0], 0x00, "expected CTAP success status");
    assert!(!result.post_handshake.is_empty());
    Ok(())
}

/// A phone (or tunnel server) that connects but never answers the handshake
/// must not hold the transaction forever: the desktop gives up after its
/// handshake timeout.
#[tokio::test]
async fn a_stalled_handshake_times_out() -> Result<()> {
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
        &[qr::TRANSPORT_WEBSOCKET],
    );
    let parsed = qr::parse_qr_url(&qr_url).unwrap();

    let (eid_tx, eid_rx) = oneshot::channel::<[u8; 16]>();
    let phone_base = base.clone();
    let phone_task = tokio::spawn(async move {
        let r = async {
            let (outcome, _ws, _psk) =
                phone::phone_setup(&phone_base, &parsed.secret, None).await?;
            eid_tx
                .send(outcome.plaintext_eid)
                .map_err(|_| anyhow::anyhow!("eid send"))?;
            // Stall: hold the tunnel open but never answer the handshake.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
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
        channel: ucabled::session::Channel::Websocket,
        qr_secret,
        identity,
        plaintext_eid,
        handshake_timeout: std::time::Duration::from_millis(500),
        connect_timeout: ucabled::tunnel::DIAL_TIMEOUT,
    };

    let start = std::time::Instant::now();
    let result = flow.run(&[0x04]).await;
    let elapsed = start.elapsed();
    phone_task.abort();

    let outcome = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
    assert!(
        matches!(result, Err(TransactionError::Timeout)),
        "a stalled handshake must time out, got {outcome:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the stall was not bounded by the handshake timeout: {elapsed:?}"
    );
    Ok(())
}

/// Real phones keep the tunnel open after the transaction instead of closing
/// it. The desktop must still hand the CTAP reply back promptly: an earlier
/// version listened for linking update messages after shutdown, delaying
/// every operation by the whole listening window.
#[tokio::test]
async fn reply_is_not_delayed_by_a_lingering_phone() -> Result<()> {
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
        &[qr::TRANSPORT_WEBSOCKET],
    );
    let parsed = qr::parse_qr_url(&qr_url).unwrap();
    let peer_public = p256::PublicKey::from_sec1_bytes(&parsed.compressed_public_key).unwrap();
    let peer_identity = peer_public.to_encoded_point(false).as_bytes().to_vec();

    let (eid_tx, eid_rx) = oneshot::channel::<[u8; 16]>();
    let phone_base = base.clone();
    let phone_task = tokio::spawn(async move {
        let r = async {
            let (outcome, mut ws, psk) =
                phone::phone_setup(&phone_base, &parsed.secret, None).await?;
            eid_tx
                .send(outcome.plaintext_eid)
                .map_err(|_| anyhow::anyhow!("eid send"))?;

            let initial = ucabled::tunnel::read_binary(&mut ws).await?;
            let (response, crypter, handshake_hash) =
                ucabled::handshake::respond_qr(&psk, &peer_identity, &initial)
                    .ok_or_else(|| anyhow::anyhow!("handshake failed"))?;
            ucabled::tunnel::write_binary(&mut ws, response).await?;

            let mut link = phone::CableLink {
                transport: phone::CableTransport::Websocket(Box::new(ws)),
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
                    Ok((phone::MSG_CTAP, _)) => {
                        link.send_ctap(&[0x00, 0xa1, 0x01, 0x40]).await?;
                    }
                    Ok((phone::MSG_SHUTDOWN, _)) => {
                        // Linger like a real phone: keep the tunnel open.
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
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
        channel: ucabled::session::Channel::Websocket,
        qr_secret,
        identity,
        plaintext_eid,
        handshake_timeout: ucabled::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: ucabled::tunnel::DIAL_TIMEOUT,
    };

    let start = std::time::Instant::now();
    let result = flow.run(&[0x04]).await?;
    let elapsed = start.elapsed();
    phone_task.abort();

    assert_eq!(result.ctap_reply[0], 0x00, "expected CTAP success status");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "CTAP reply waited for the lingering phone: {elapsed:?}"
    );
    Ok(())
}
