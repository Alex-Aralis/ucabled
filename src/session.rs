// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use p256::SecretKey;
use std::time::Duration;
use zeroize::Zeroize;

use crate::eid;
use crate::error::TransactionError;
use crate::handshake::HandshakeInitiator;
use crate::kdf::{Purpose, derive};
use crate::phone::{CableLink, CableTransport, MSG_CTAP, MSG_SHUTDOWN, MSG_UPDATE};
use crate::tunnel::{self, decode_tunnel_server_domain};

/// The phone sends the handshake response immediately after the tunnel
/// connects, so a stall means a dead phone or a malicious tunnel server;
/// without a bound the HID channel would stay busy until the user cancels.
pub const HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// The phone sends the post-handshake message right after the handshake.
const POST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for the phone's answer to one CTAP command; the user may still
/// be confirming on the phone. Firefox gives the whole operation 5 minutes.
const CTAP_REPLY_TIMEOUT: Duration = Duration::from_secs(300);

/// Which data transfer channel the authenticator chose.
pub enum Channel {
    /// The default WebSocket tunnel server path.
    Websocket,
    /// The CTAP 2.3 optional BLE data channel: an LE L2CAP CoC identified by
    /// the server PSM from the advertisement suffix.
    #[cfg(feature = "l2cap")]
    L2cap {
        address: bluer::Address,
        address_type: bluer::AddressType,
        psm: u16,
    },
}

pub struct DesktopFlow {
    /// e.g. "wss://cable.ua5v.com" or "ws://127.0.0.1:9000" for tests.
    pub tunnel_base: Option<String>,
    /// Channel selected from the BLE advert (WebSocket unless it carried a PSM).
    pub channel: Channel,
    pub qr_secret: [u8; 16],
    pub identity: SecretKey,
    pub plaintext_eid: [u8; eid::EID_PLAINTEXT_SIZE],
    /// How long to wait for the phone's handshake response; a field so that
    /// tests can shrink it.
    pub handshake_timeout: Duration,
    /// Budget for establishing the BLE L2CAP channel before falling back to
    /// the WebSocket channel; a field so that tests can shrink it.
    pub connect_timeout: Duration,
}

/// Result of a completed desktop-side caBLE session.
pub struct DesktopResult {
    /// Raw CBOR of the post-handshake message from the phone.
    pub post_handshake: Vec<u8>,
    /// First CTAP reply payload (status byte + CBOR) received from the phone.
    pub ctap_reply: Vec<u8>,
    pub handshake_hash: [u8; 32],
}

impl DesktopFlow {
    /// Run the desktop side: connect tunnel, perform Noise handshake, read the
    /// post-handshake message, send one CTAP command, return its reply.
    pub async fn run(mut self, ctap_command: &[u8]) -> Result<DesktopResult, TransactionError> {
        let components = eid::to_components(&self.plaintext_eid);

        let mut tunnel_id = [0u8; 16];
        derive(&self.qr_secret, &[], Purpose::TunnelId, &mut tunnel_id);
        let mut psk = [0u8; 32];
        derive(&self.qr_secret, &self.plaintext_eid, Purpose::Psk, &mut psk);
        // The QR secret is no longer needed once the tunnel ID and PSK exist.
        self.qr_secret.zeroize();

        let mut transport = self
            .connect_transport(&components, &tunnel_id, ctap_command.len())
            .await?;

        let mut handshake = HandshakeInitiator::new_qr(&psk, &self.identity);
        // The PSK now lives inside the handshake state.
        psk.zeroize();
        let initial = handshake.build_initial_message();
        transport
            .send(initial)
            .await
            .map_err(TransactionError::transport)?;

        let response = tokio::time::timeout(self.handshake_timeout, transport.recv())
            .await
            .map_err(|_| TransactionError::Timeout)?
            .map_err(TransactionError::transport)?;
        let (crypter, handshake_hash) = handshake
            .process_response(&response)
            .ok_or_else(|| TransactionError::failed(anyhow::anyhow!("caBLE handshake failed")))?;
        tracing::info!("caBLE handshake complete");

        let mut link = CableLink {
            transport,
            crypter,
            handshake_hash,
        };

        let post_handshake = tokio::time::timeout(POST_HANDSHAKE_TIMEOUT, recv_raw(&mut link))
            .await
            .map_err(|_| TransactionError::Timeout)?
            .map_err(TransactionError::transport)?;
        tracing::info!(
            len = post_handshake.len(),
            "received post-handshake message"
        );

        link.send_ctap(ctap_command)
            .await
            .map_err(TransactionError::transport)?;

        // A single deadline for the whole reply wait: the tunnel server is not
        // trusted and must not be able to keep the transaction alive forever
        // by trickling update messages.
        let reply_deadline = tokio::time::Instant::now() + CTAP_REPLY_TIMEOUT;
        let ctap_reply = loop {
            let (ty, payload) = tokio::time::timeout_at(reply_deadline, link.recv_message())
                .await
                .map_err(|_| TransactionError::Timeout)?
                .map_err(TransactionError::transport)?;
            match ty {
                MSG_CTAP => break payload,
                MSG_UPDATE => {
                    tracing::info!(len = payload.len(), "received update message");
                }
                MSG_SHUTDOWN => {
                    return Err(TransactionError::failed(anyhow::anyhow!(
                        "unexpected shutdown from authenticator"
                    )));
                }
                other => {
                    return Err(TransactionError::failed(anyhow::anyhow!(
                        "unexpected message type {other}"
                    )));
                }
            }
        };

        link.send_shutdown().await.ok();

        Ok(DesktopResult {
            post_handshake,
            ctap_reply,
            handshake_hash,
        })
    }

    /// Open the data transfer channel chosen by the authenticator.
    ///
    /// `_ctap_len` is the CTAP command length; the L2CAP arm uses it to pick
    /// the WebSocket channel when the negotiated send MTU cannot carry the
    /// command.  The parameter is always accepted so the call site is the
    /// same with and without the `l2cap` feature.
    async fn connect_transport(
        &self,
        components: &eid::EidComponents,
        tunnel_id: &[u8; 16],
        _ctap_len: usize,
    ) -> Result<CableTransport, TransactionError> {
        match &self.channel {
            Channel::Websocket => self.connect_websocket(components, tunnel_id).await,
            #[cfg(feature = "l2cap")]
            Channel::L2cap {
                address,
                address_type,
                psm,
            } => {
                tracing::info!(%address, psm, "connecting caBLE L2CAP channel");
                // Largest message the desktop will send on this channel:
                // the 4-byte length prefix (PXP §6.1.2), the caBLE type byte
                // and the CTAP command, padded and tagged by the crypter.
                // The handshake messages that go out before the crypter are
                // smaller for any plausible request.
                let required = crate::l2cap::LENGTH_PREFIX
                    + crate::crypter::Crypter::encrypted_size(1 + _ctap_len);
                // A phone that advertised a PSM but never answers (stale
                // address, moved out of range) must not hold the transaction
                // until the host times out.
                let connect = tokio::time::timeout(
                    self.connect_timeout,
                    crate::l2cap::connect(*address, *address_type, *psm),
                )
                .await;
                match connect {
                    Ok(Ok(stream)) => {
                        // Each caBLE message is one L2CAP SDU, so a command
                        // larger than the peer's receive MTU cannot be sent at
                        // all.  The spec lets the authenticator attempt more
                        // than one channel from the QR intersection, so fall
                        // back to the tunnel instead of failing the send.
                        match crate::l2cap::send_mtu(&stream) {
                            Some(mtu) if mtu < required => {
                                tracing::warn!(
                                    mtu,
                                    required,
                                    "L2CAP send MTU too small for this command; \
                                     trying the WebSocket channel"
                                );
                                self.connect_websocket(components, tunnel_id).await
                            }
                            _ => Ok(CableTransport::L2cap(stream)),
                        }
                    }
                    // The spec lets the authenticator attempt more than one
                    // channel from the QR intersection, so a WebSocket retry
                    // can still succeed. It is bounded by the dial timeout if
                    // the phone only listens on BLE.
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "L2CAP connect failed ({e:#}); trying the WebSocket channel"
                        );
                        self.connect_websocket(components, tunnel_id).await
                    }
                    Err(_) => {
                        tracing::warn!("L2CAP connect timed out; trying the WebSocket channel");
                        self.connect_websocket(components, tunnel_id).await
                    }
                }
            }
        }
    }

    /// The default channel: the tunnel server over WebSockets.
    async fn connect_websocket(
        &self,
        components: &eid::EidComponents,
        tunnel_id: &[u8; 16],
    ) -> Result<CableTransport, TransactionError> {
        let domain =
            decode_tunnel_server_domain(components.tunnel_server_domain).ok_or_else(|| {
                TransactionError::failed(anyhow::anyhow!("unknown tunnel server domain"))
            })?;
        let tunnel_base = self
            .tunnel_base
            .clone()
            .unwrap_or_else(|| format!("wss://{domain}"));
        let url = format!(
            "{tunnel_base}/cable/connect/{}/{}",
            hex::encode(components.routing_id),
            hex::encode(tunnel_id)
        );
        tracing::info!("connecting caBLE tunnel");
        let (ws, _response) = tunnel::dial(&url)
            .await
            .map_err(TransactionError::transport)?;
        Ok(CableTransport::Websocket(Box::new(ws)))
    }
}

async fn recv_raw(link: &mut CableLink) -> Result<Vec<u8>> {
    let ct = link.transport.recv().await?;
    link.crypter.decrypt(&ct).context("decrypt failed")
}
