//! End-to-end encryption: a user passphrase → Argon2id → XChaCha20-Poly1305.
//! The server never sees plaintext or keys.

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};

use crate::model::Envelope;

/// Derive the 32-byte message key from the user's passphrase. The salt is bound
/// to the username so the same passphrase yields the same key on all of the
/// user's devices (and differs between users).
pub fn derive_key(passphrase: &str, username: &str) -> Option<[u8; 32]> {
    let salt = format!("my-domain-e2ee:{username}");
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut key)
        .ok()?;
    Some(key)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Option<Envelope> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).ok()?;
    Some(Envelope {
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ct),
    })
}

pub fn decrypt(key: &[u8; 32], env: &Envelope) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = STANDARD.decode(&env.nonce).ok()?;
    if nonce.len() != 24 {
        return None;
    }
    let ct = STANDARD.decode(&env.ciphertext).ok()?;
    cipher.decrypt(XNonce::from_slice(&nonce), ct.as_ref()).ok()
}

/// Generate a random 24-byte key, base64-encoded (UI "Generate" helper).
pub fn generate_key() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}
