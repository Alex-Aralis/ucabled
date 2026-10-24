// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use std::time::Duration;
use zeroize::Zeroize;

use crate::ble::{AdvertObservation, BleError};
use crate::error::TransactionError;
use crate::kdf::{Purpose, derive};
use crate::qr::{self, RequestType};
use crate::session::{Channel, DesktopFlow};
use crate::{NUM_ASSIGNED_TUNNEL_DOMAINS, eid};

/// How long the QR code stays valid while waiting for the phone's BLE advert.
pub const BLE_ADVERT_TIMEOUT: Duration = Duration::from_secs(300);

/// Whether to offer the CTAP 2.3 BLE data channel in the QR code.
///
/// Experimental: the L2CAP framing has not been verified against real phones,
/// so it is off by default. It also requires a build with the `l2cap` feature;
/// opt in with `UCABLED_BLE_CHANNEL=1`.
fn ble_channel_enabled() -> bool {
    #[cfg(feature = "l2cap")]
    {
        std::env::var("UCABLED_BLE_CHANNEL").is_ok_and(|v| !v.is_empty() && v != "0")
    }
    #[cfg(not(feature = "l2cap"))]
    {
        false
    }
}

/// Run one full caBLE QR transaction: show a QR code, wait for the phone's
/// BLE advert, do the handshake over the chosen channel, forward the CTAP
/// command and return the phone's CTAP response payload (status byte + CBOR).
///
/// `on_qr` is invoked with the QR contents once; the caller decides how to
/// present it (terminal, GTK window, ...). `on_advert` is invoked when the
/// phone's BLE advert has been received, so the UI can stop waiting.
///
/// `identity` is the daemon's persistent identity key (see
/// [`crate::identity`]); its public key goes into the QR code.
pub async fn run_qr_transaction(
    ctap_command: &[u8],
    request_type: RequestType,
    identity: &SecretKey,
    on_qr: impl FnOnce(&str),
    on_advert: impl FnOnce(),
) -> Result<Vec<u8>, TransactionError> {
    let compressed = identity.public_key().to_encoded_point(true);
    let compressed: &[u8; 33] = compressed.as_bytes().try_into().unwrap();

    let mut qr_secret = [0u8; 16];
    OsRng.fill_bytes(&mut qr_secret);

    // Linking is not offered: iOS never implemented it, Android stopped
    // sending linking information, and Chrome disabled hybrid linking for
    // WebAuthn in 2024 (see docs/linking.md).
    let offer_ble = ble_channel_enabled();
    let mut channels = vec![qr::TRANSPORT_WEBSOCKET];
    if offer_ble {
        channels.push(qr::TRANSPORT_BLE);
    }
    let qr_url = qr::encode_qr_url(
        compressed,
        &qr_secret,
        NUM_ASSIGNED_TUNNEL_DOMAINS,
        false,
        request_type,
        &channels,
    );
    on_qr(&qr_url);

    let mut eid_key = [0u8; eid::EID_KEY_SIZE];
    derive(&qr_secret, &[], Purpose::EidKey, &mut eid_key);

    // The EID key decrypts only the advertisement, so erase it once the
    // advert wait is over — on every outcome, like the QR secret and PSK.
    let advert = crate::ble::await_advert_full(&eid_key, BLE_ADVERT_TIMEOUT).await;
    eid_key.zeroize();
    let advert = match advert {
        Ok(advert) => advert,
        Err(BleError::Timeout) => return Err(TransactionError::Timeout),
        Err(BleError::Backend(e)) => return Err(TransactionError::transport(e)),
    };
    on_advert();
    tracing::info!("received valid caBLE advert");

    let channel = select_channel(&advert, offer_ble);

    let flow = DesktopFlow {
        tunnel_base: None,
        channel,
        qr_secret,
        identity: identity.clone(),
        plaintext_eid: advert.plaintext_eid,
        handshake_timeout: crate::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: crate::tunnel::DIAL_TIMEOUT,
    };
    let result = flow.run(ctap_command).await?;
    Ok(result.ctap_reply)
}

/// Pick the data transfer channel from the advert: the L2CAP CoC if the phone
/// offered a PSM and we advertised BLE, otherwise the WebSocket tunnel.
fn select_channel(advert: &AdvertObservation, offer_ble: bool) -> Channel {
    #[cfg(feature = "l2cap")]
    if offer_ble && let Some(psm) = advert.psm {
        tracing::info!(psm, "phone offered the BLE L2CAP channel");
        return Channel::L2cap {
            address: advert.address,
            address_type: advert.address_type,
            psm,
        };
    }

    #[cfg(not(feature = "l2cap"))]
    let _ = (advert, offer_ble);
    Channel::Websocket
}
