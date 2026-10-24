// SPDX-License-Identifier: GPL-3.0-or-later

pub mod advert;
pub mod agent;
pub mod cbor;
pub mod crypter;
pub mod ctap;
pub mod ctaphid;
pub mod eid;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod noise;
pub mod notify;
pub mod phone;
pub mod qr;
#[cfg(feature = "ble")]
pub mod relay;
pub mod session;
pub mod tunnel;
pub mod uhid_dev;
pub mod uhid_perm;
pub mod ui;

#[cfg(feature = "ble")]
pub mod ble;

#[cfg(feature = "l2cap")]
pub mod l2cap;

pub const NUM_ASSIGNED_TUNNEL_DOMAINS: u8 = tunnel::ASSIGNED_TUNNEL_DOMAINS.len() as u8;
pub const WS_SUBPROTOCOL: &str = "fido.cable";
pub const CABLE_BLE_UUID: &str = "0000fff9-0000-1000-8000-00805f9b34fb";
