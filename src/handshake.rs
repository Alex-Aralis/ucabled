// SPDX-License-Identifier: GPL-3.0-or-later

use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::crypter::Crypter;
use crate::noise::{KN_PSK0_PROTOCOL_NAME, NK_PSK0_PROTOCOL_NAME, Noise};

pub const P256_X962_LENGTH: usize = 65;
pub const RESPONSE_SIZE: usize = P256_X962_LENGTH + 16;

fn uncompressed_point(key: &PublicKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

fn parse_point(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).ok()
}

fn ecdh(secret: &SecretKey, peer_bytes: &[u8]) -> Option<[u8; 32]> {
    let peer = parse_point(peer_bytes)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let x: &[u8] = shared.raw_secret_bytes();
    x.try_into().ok()
}

pub struct HandshakeInitiator {
    noise: Noise,
    identity: Option<SecretKey>,
    #[allow(dead_code)]
    peer_identity: Option<Vec<u8>>,
    ephemeral: Option<SecretKey>,
    ephemeral_public: Vec<u8>,
}

impl HandshakeInitiator {
    /// QR handshake (KNpsk0): local identity key whose public key is in the QR code.
    pub fn new_qr(psk: &[u8; 32], identity: &SecretKey) -> Self {
        let mut noise = Noise::new(KN_PSK0_PROTOCOL_NAME);
        noise.mix_hash(&[1]);
        noise.mix_hash(&uncompressed_point(&identity.public_key()));
        noise.mix_key_and_hash(psk);

        let ephemeral = SecretKey::random(&mut OsRng);
        let ephemeral_public = uncompressed_point(&ephemeral.public_key());
        noise.mix_hash(&ephemeral_public);
        noise.mix_key(&ephemeral_public);

        Self {
            noise,
            identity: Some(identity.clone()),
            peer_identity: None,
            ephemeral: Some(ephemeral),
            ephemeral_public,
        }
    }

    /// Paired handshake (NKpsk0): peer identity known from linking info.
    ///
    /// Returns `None` when `peer_identity_x962` is not a valid curve point:
    /// the static-shared secret is what authenticates the paired peer, so
    /// mixing it must not be skipped silently.
    #[allow(dead_code)]
    pub fn new_paired(psk: &[u8; 32], peer_identity_x962: &[u8]) -> Option<Self> {
        let mut noise = Noise::new(NK_PSK0_PROTOCOL_NAME);
        noise.mix_hash(&[0]);
        noise.mix_hash(peer_identity_x962);
        noise.mix_key_and_hash(psk);

        let ephemeral = SecretKey::random(&mut OsRng);
        let ephemeral_public = uncompressed_point(&ephemeral.public_key());
        noise.mix_hash(&ephemeral_public);
        noise.mix_key(&ephemeral_public);

        let es = ecdh(&ephemeral, peer_identity_x962)?;
        noise.mix_key(&es);

        Some(Self {
            noise,
            identity: None,
            peer_identity: Some(peer_identity_x962.to_vec()),
            ephemeral: Some(ephemeral),
            ephemeral_public,
        })
    }

    pub fn build_initial_message(&mut self) -> Vec<u8> {
        let ct = self.noise.encrypt_and_hash(&[]);
        let mut msg = self.ephemeral_public.clone();
        msg.extend_from_slice(&ct);
        msg
    }

    pub fn process_response(mut self, response: &[u8]) -> Option<(Crypter, [u8; 32])> {
        if response.len() != RESPONSE_SIZE {
            return None;
        }
        let (peer_point_bytes, ciphertext) = response.split_at(P256_X962_LENGTH);

        let ephemeral = self.ephemeral.take()?;
        let mut shared_ee = ecdh(&ephemeral, peer_point_bytes)?;

        self.noise.mix_hash(peer_point_bytes);
        self.noise.mix_key(peer_point_bytes);
        self.noise.mix_key(&shared_ee);
        // The raw ECDH output is a plain array, not a zeroizing type, so
        // wipe it once it is mixed in.
        shared_ee.zeroize();

        if let Some(identity) = &self.identity {
            let mut shared_se = ecdh(identity, peer_point_bytes)?;
            self.noise.mix_key(&shared_se);
            shared_se.zeroize();
        }

        let plaintext = self.noise.decrypt_and_hash(ciphertext)?;
        if !plaintext.is_empty() {
            return None;
        }

        let (write_key, read_key) = self.noise.traffic_keys();
        Some((
            Crypter::new(read_key, write_key),
            self.noise.handshake_hash(),
        ))
    }
}

/// Phone side: respond to a QR handshake (KNpsk0). Peer identity is the
/// uncompressed public key from the QR code.
pub fn respond_qr(
    psk: &[u8; 32],
    peer_identity_x962: &[u8],
    initial_message: &[u8],
) -> Option<(Vec<u8>, Crypter, [u8; 32])> {
    respond_inner(
        KN_PSK0_PROTOCOL_NAME,
        Some(psk),
        None,
        Some(peer_identity_x962),
        initial_message,
        true,
    )
}

/// Phone side: respond to a paired handshake (NKpsk0) with a local identity.
#[allow(dead_code)]
pub fn respond_paired(
    psk: &[u8; 32],
    identity: &SecretKey,
    initial_message: &[u8],
) -> Option<(Vec<u8>, Crypter, [u8; 32])> {
    respond_inner(
        NK_PSK0_PROTOCOL_NAME,
        Some(psk),
        Some(identity.clone()),
        None,
        initial_message,
        false,
    )
}

fn respond_inner(
    protocol: &[u8],
    psk: Option<&[u8; 32]>,
    identity: Option<SecretKey>,
    peer_identity: Option<&[u8]>,
    initial_message: &[u8],
    qr_prologue: bool,
) -> Option<(Vec<u8>, Crypter, [u8; 32])> {
    if initial_message.len() < P256_X962_LENGTH {
        return None;
    }
    let (peer_point_bytes, ciphertext) = initial_message.split_at(P256_X962_LENGTH);

    let mut noise = Noise::new(protocol);
    noise.mix_hash(&[qr_prologue as u8]);
    if let Some(id) = &identity {
        noise.mix_hash(&uncompressed_point(&id.public_key()));
    } else if let Some(peer) = peer_identity {
        noise.mix_hash(peer);
    }
    if let Some(psk) = psk {
        noise.mix_key_and_hash(psk);
    }

    noise.mix_hash(peer_point_bytes);
    noise.mix_key(peer_point_bytes);

    let ephemeral = SecretKey::random(&mut OsRng);
    parse_point(peer_point_bytes)?;

    if let Some(id) = &identity {
        let mut es = ecdh(id, peer_point_bytes)?;
        noise.mix_key(&es);
        es.zeroize();
    }

    let plaintext = noise.decrypt_and_hash(ciphertext)?;
    if !plaintext.is_empty() {
        return None;
    }

    let ephemeral_public = uncompressed_point(&ephemeral.public_key());
    noise.mix_hash(&ephemeral_public);
    noise.mix_key(&ephemeral_public);

    let mut shared_ee = ecdh(&ephemeral, peer_point_bytes)?;
    noise.mix_key(&shared_ee);
    shared_ee.zeroize();

    if let Some(peer) = peer_identity {
        let mut shared_se = ecdh(&ephemeral, peer)?;
        noise.mix_key(&shared_se);
        shared_se.zeroize();
    }

    let my_ciphertext = noise.encrypt_and_hash(&[]);
    let mut response = ephemeral_public;
    response.extend_from_slice(&my_ciphertext);

    let (read_key, write_key) = noise.traffic_keys();
    Some((
        response,
        Crypter::new(read_key, write_key),
        noise.handshake_hash(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; 32] = [7u8; 32];

    fn identity() -> (SecretKey, Vec<u8>) {
        let secret = SecretKey::random(&mut OsRng);
        let public = uncompressed_point(&secret.public_key());
        (secret, public)
    }

    fn qr_initiator(psk: &[u8; 32], identity: &SecretKey) -> (HandshakeInitiator, Vec<u8>) {
        let mut init = HandshakeInitiator::new_qr(psk, identity);
        let msg = init.build_initial_message();
        (init, msg)
    }

    /// A completed QR handshake: a fresh initiator plus the honest
    /// responder's reply, not yet consumed by `process_response`.
    fn qr_init_and_response() -> (HandshakeInitiator, Vec<u8>) {
        let (secret, public) = identity();
        let (init, msg) = qr_initiator(&PSK, &secret);
        let (response, _phone, _hh) = respond_qr(&PSK, &public, &msg).unwrap();
        (init, response)
    }

    #[test]
    fn paired_initiator_rejects_an_invalid_peer_identity() {
        // Not a curve point: the static-shared secret authenticates the
        // paired peer, so the initiator must fail rather than continue
        // without it.
        assert!(HandshakeInitiator::new_paired(&PSK, &[0u8; P256_X962_LENGTH]).is_none());
        // Truncated point.
        assert!(HandshakeInitiator::new_paired(&PSK, &[4u8; 20]).is_none());
    }

    #[test]
    fn qr_roundtrip_derives_a_working_channel() {
        let (secret, public) = identity();
        let (init, msg) = qr_initiator(&PSK, &secret);
        let (response, mut phone, hh_phone) = respond_qr(&PSK, &public, &msg).unwrap();
        let (mut desktop, hh_desktop) = init.process_response(&response).unwrap();
        assert_eq!(hh_desktop, hh_phone);
        let ct = desktop.encrypt(b"ping").unwrap();
        assert_eq!(phone.decrypt(&ct).unwrap(), b"ping");
        let ct = phone.encrypt(b"pong").unwrap();
        assert_eq!(desktop.decrypt(&ct).unwrap(), b"pong");
    }

    #[test]
    fn paired_roundtrip_derives_a_working_channel() {
        let (phone_secret, phone_public) = identity();
        let mut init = HandshakeInitiator::new_paired(&PSK, &phone_public).unwrap();
        let msg = init.build_initial_message();
        let (response, mut phone, hh_phone) = respond_paired(&PSK, &phone_secret, &msg).unwrap();
        let (mut desktop, hh_desktop) = init.process_response(&response).unwrap();
        assert_eq!(hh_desktop, hh_phone);
        let ct = phone.encrypt(b"pong").unwrap();
        assert_eq!(desktop.decrypt(&ct).unwrap(), b"pong");
    }

    #[test]
    fn wrong_psk_fails_whichever_side_has_it() {
        let wrong = [9u8; 32];
        // The initial message is encrypted under the psk, so a responder
        // with a different psk cannot decrypt it — regardless of which
        // side is the wrong one.
        let (secret, public) = identity();
        let (_init, msg) = qr_initiator(&wrong, &secret);
        assert!(respond_qr(&PSK, &public, &msg).is_none());
        let (_init, msg) = qr_initiator(&PSK, &secret);
        assert!(respond_qr(&wrong, &public, &msg).is_none());

        // Same for the paired (NKpsk0) flow.
        let (phone_secret, phone_public) = identity();
        let mut init = HandshakeInitiator::new_paired(&wrong, &phone_public).unwrap();
        let msg = init.build_initial_message();
        assert!(respond_paired(&PSK, &phone_secret, &msg).is_none());
    }

    #[test]
    fn wrong_identity_public_key_fails_the_responder() {
        // The QR carries the desktop identity; responding against a
        // different identity changes the handshake hash and the se key.
        let (secret, _public) = identity();
        let (_other, other_public) = identity();
        let (_init, msg) = qr_initiator(&PSK, &secret);
        assert!(respond_qr(&PSK, &other_public, &msg).is_none());
    }

    #[test]
    fn tampered_initial_message_is_rejected() {
        let (secret, public) = identity();
        let (_init, msg) = qr_initiator(&PSK, &secret);

        // Flip a ciphertext byte: the tag no longer verifies.
        let mut bad = msg.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(respond_qr(&PSK, &public, &bad).is_none());

        // Swap in a different *valid* ephemeral point: ee and the hash
        // change, so decryption still fails.
        let (_other, other_public) = identity();
        let mut bad = other_public;
        bad.extend_from_slice(&msg[P256_X962_LENGTH..]);
        assert!(respond_qr(&PSK, &public, &bad).is_none());
    }

    #[test]
    fn malformed_initial_message_is_rejected() {
        let (secret, public) = identity();
        let (_init, msg) = qr_initiator(&PSK, &secret);

        // Shorter than a point.
        assert!(respond_qr(&PSK, &public, &msg[..P256_X962_LENGTH - 1]).is_none());
        // A point with no ciphertext at all.
        assert!(respond_qr(&PSK, &public, &msg[..P256_X962_LENGTH]).is_none());
        // Extra trailing garbage becomes part of the ciphertext.
        let mut bad = msg.clone();
        bad.push(0);
        assert!(respond_qr(&PSK, &public, &bad).is_none());
        // Not a curve point at all.
        let mut bad = vec![0u8; P256_X962_LENGTH];
        bad.extend_from_slice(&msg[P256_X962_LENGTH..]);
        assert!(respond_qr(&PSK, &public, &bad).is_none());
    }

    #[test]
    fn tampered_response_is_rejected() {
        // Flip a ciphertext byte.
        let (init, response) = qr_init_and_response();
        let mut bad = response.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(init.process_response(&bad).is_none());

        // Swap in a different *valid* ephemeral point.
        let (init, response) = qr_init_and_response();
        let (_other, other_public) = identity();
        let mut bad = other_public;
        bad.extend_from_slice(&response[P256_X962_LENGTH..]);
        assert!(init.process_response(&bad).is_none());

        // Truncated and extended responses fail the length check.
        let (init, response) = qr_init_and_response();
        assert!(
            init.process_response(&response[..RESPONSE_SIZE - 1])
                .is_none()
        );
        let (init, response) = qr_init_and_response();
        let mut bad = response.clone();
        bad.push(0);
        assert!(init.process_response(&bad).is_none());

        // Not a curve point at all.
        let (init, response) = qr_init_and_response();
        let mut bad = vec![0u8; P256_X962_LENGTH];
        bad.extend_from_slice(&response[P256_X962_LENGTH..]);
        assert!(init.process_response(&bad).is_none());
    }

    #[test]
    fn a_response_from_another_transaction_is_rejected() {
        // Replaying a response into a different initiator must fail: ee
        // does not match.
        let (init_a, _response_a) = qr_init_and_response();
        let (init_b, response_b) = qr_init_and_response();
        assert!(init_a.process_response(&response_b).is_none());
        let (init_a, response_a) = qr_init_and_response();
        assert!(init_b.process_response(&response_a).is_none());
        let _ = init_a;
    }

    #[test]
    fn qr_and_paired_handshakes_do_not_mix() {
        // The protocol name is hashed in first, so a responder of the
        // other flow cannot even decrypt the initial message.
        let (desktop_secret, desktop_public) = identity();
        let (phone_secret, phone_public) = identity();

        let (_init, qr_msg) = qr_initiator(&PSK, &desktop_secret);
        assert!(respond_paired(&PSK, &phone_secret, &qr_msg).is_none());

        let mut paired_init = HandshakeInitiator::new_paired(&PSK, &phone_public).unwrap();
        let paired_msg = paired_init.build_initial_message();
        assert!(respond_qr(&PSK, &desktop_public, &paired_msg).is_none());
    }

    #[test]
    fn an_initial_message_with_a_payload_is_rejected() {
        // The handshake messages must encrypt an empty payload. Build a
        // syntactically valid initial message whose plaintext is not
        // empty and check the responder refuses it.
        let (desktop_secret, desktop_public) = identity();
        let mut noise = Noise::new(KN_PSK0_PROTOCOL_NAME);
        noise.mix_hash(&[1]);
        noise.mix_hash(&desktop_public);
        noise.mix_key_and_hash(&PSK);
        let ephemeral = SecretKey::random(&mut OsRng);
        let ephemeral_public = uncompressed_point(&ephemeral.public_key());
        noise.mix_hash(&ephemeral_public);
        noise.mix_key(&ephemeral_public);
        let ct = noise.encrypt_and_hash(b"unexpected");
        let mut msg = ephemeral_public;
        msg.extend_from_slice(&ct);
        let _ = desktop_secret;
        assert!(respond_qr(&PSK, &desktop_public, &msg).is_none());
    }

    #[test]
    fn a_response_with_a_payload_is_rejected() {
        // Mirror image: an honest responder's state up to the response
        // encryption, but with a non-empty payload. The initiator must
        // refuse it.
        let (desktop_secret, desktop_public) = identity();
        let (init, msg) = qr_initiator(&PSK, &desktop_secret);

        let (peer_point_bytes, ciphertext) = msg.split_at(P256_X962_LENGTH);
        let mut noise = Noise::new(KN_PSK0_PROTOCOL_NAME);
        noise.mix_hash(&[1]);
        noise.mix_hash(&desktop_public);
        noise.mix_key_and_hash(&PSK);
        noise.mix_hash(peer_point_bytes);
        noise.mix_key(peer_point_bytes);
        assert_eq!(noise.decrypt_and_hash(ciphertext).unwrap(), b"");
        let ephemeral = SecretKey::random(&mut OsRng);
        let ephemeral_public = uncompressed_point(&ephemeral.public_key());
        noise.mix_hash(&ephemeral_public);
        noise.mix_key(&ephemeral_public);
        let ee = ecdh(&ephemeral, peer_point_bytes).unwrap();
        noise.mix_key(&ee);
        let se = ecdh(&ephemeral, &desktop_public).unwrap();
        noise.mix_key(&se);
        let ct = noise.encrypt_and_hash(b"unexpected");
        let mut response = ephemeral_public;
        response.extend_from_slice(&ct);
        assert!(init.process_response(&response).is_none());
    }
}
