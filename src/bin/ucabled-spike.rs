// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;

use ucabled::ctap::CMD_GET_INFO;
use ucabled::kdf::{Purpose, derive};
use ucabled::qr::{self, RequestType};
use ucabled::session::DesktopFlow;
use ucabled::{NUM_ASSIGNED_TUNNEL_DOMAINS, eid};

#[derive(Default)]
struct Args {
    advert_hex: Option<String>,
    tunnel_base: Option<String>,
    make_credential: bool,
    cmd_hex: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--advert-hex" => {
                args.advert_hex = Some(it.next().context("--advert-hex needs a value")?)
            }
            "--tunnel-base" => {
                args.tunnel_base = Some(it.next().context("--tunnel-base needs a value")?)
            }
            "--mc" => args.make_credential = true,
            "--cmd" => args.cmd_hex = Some(it.next().context("--cmd needs a value")?),
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = parse_args()?;

    let identity = SecretKey::random(&mut OsRng);
    let compressed = identity.public_key().to_encoded_point(true);
    let compressed: &[u8; qr::COMPRESSED_PUBLIC_KEY_SIZE] =
        compressed.as_bytes().try_into().unwrap();

    let mut qr_secret = [0u8; qr::QR_SECRET_SIZE];
    OsRng.fill_bytes(&mut qr_secret);

    let request_type = if args.make_credential {
        RequestType::MakeCredential
    } else {
        RequestType::GetAssertion
    };
    let qr_url = qr::encode_qr_url(
        compressed,
        &qr_secret,
        NUM_ASSIGNED_TUNNEL_DOMAINS,
        true, // supports_linking (L0: verify whether phones send linking data)
        request_type,
        &[qr::TRANSPORT_WEBSOCKET],
    );

    println!("caBLE QR URL: {qr_url}");
    let code = qrcode::QrCode::new(qr_url.as_bytes())?;
    let image = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Dark)
        .light_color(qrcode::render::unicode::Dense1x2::Light)
        .build();
    println!("{image}");
    println!("Scan with your phone (iCloud Keychain / Google Password Manager).");

    let mut eid_key = [0u8; eid::EID_KEY_SIZE];
    derive(&qr_secret, &[], Purpose::EidKey, &mut eid_key);

    let plaintext_eid: [u8; eid::EID_PLAINTEXT_SIZE] = if let Some(advert_hex) = &args.advert_hex {
        let advert = hex::decode(advert_hex.trim()).context("bad --advert-hex")?;
        eid::decrypt(&advert, &eid_key).context("advert failed trial decrypt")?
    } else {
        #[cfg(feature = "ble")]
        {
            println!("Scanning for BLE advert...");
            ucabled::ble::await_advert(&eid_key, ucabled::relay::BLE_ADVERT_TIMEOUT).await?
        }
        #[cfg(not(feature = "ble"))]
        {
            anyhow::bail!(
                "built without BLE support; pass --advert-hex or build with --features ble"
            );
        }
    };
    println!(
        "Received valid caBLE advert: {}",
        hex::encode(plaintext_eid)
    );

    let cmd = match &args.cmd_hex {
        Some(h) => hex::decode(h.trim())?,
        None => vec![CMD_GET_INFO],
    };

    let flow = DesktopFlow {
        tunnel_base: args.tunnel_base,
        channel: ucabled::session::Channel::Websocket,
        qr_secret,
        identity,
        plaintext_eid,
        handshake_timeout: ucabled::session::HANDSHAKE_RESPONSE_TIMEOUT,
        connect_timeout: ucabled::tunnel::DIAL_TIMEOUT,
    };
    let result = flow.run(&cmd).await?;

    println!("handshake hash: {}", hex::encode(result.handshake_hash));
    println!(
        "post-handshake message ({} bytes): {}",
        result.post_handshake.len(),
        hex::encode(&result.post_handshake)
    );
    println!(
        "CTAP reply ({} bytes): {}",
        result.ctap_reply.len(),
        hex::encode(&result.ctap_reply)
    );
    Ok(())
}
