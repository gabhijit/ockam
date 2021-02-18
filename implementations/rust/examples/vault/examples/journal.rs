/// With the Ockam Vault, I can manage and use secrets to secure my data.
/// I can encrypt my data with a block cipher using a secret key stored in the Vault.
/// I can sign and verify my data with a public and private keypair stored in the Vault.
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};

use ockam_vault::ockam_vault_core::{
    Secret, SecretAttributes, SecretPersistence, SecretType, SecretVault, Signer, SymmetricVault,
    Verifier, AES256_SECRET_LENGTH, CURVE25519_SECRET_LENGTH,
};
use ockam_vault::SoftwareVault;

type Bytes = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
struct Entry {
    message: Option<String>,
    payload: Option<Bytes>,
    signature: Option<Bytes>,
}

impl Entry {
    fn new<S: ToString>(s: S) -> Self {
        Entry {
            message: Some(s.to_string()),
            payload: None,
            signature: None,
        }
    }

    fn is_encrypted(&self) -> bool {
        self.payload.is_some()
    }

    fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

impl Display for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;

        if self.is_encrypted() {
            write!(f, "<ENCRYPTED>")?;
        }

        if self.is_signed() {
            write!(f, "<SIGNED>")?;
        }
        write!(f, "]")
    }
}

struct Journal {
    entries: BTreeSet<Entry>,
    vault: SoftwareVault,
    encryption_secret: Secret,
    signing_secret: Secret,
}

impl Default for Journal {
    fn default() -> Self {
        let mut vault = SoftwareVault::default();

        let aes = SecretAttributes::new(
            SecretType::Aes,
            SecretPersistence::Ephemeral,
            AES256_SECRET_LENGTH,
        );

        let encryption_secret = match vault.secret_generate(aes) {
            Ok(secret) => secret,
            Err(e) => panic!("{}", e),
        };

        let ecdh = SecretAttributes::new(
            SecretType::Curve25519,
            SecretPersistence::Persistent,
            CURVE25519_SECRET_LENGTH,
        );

        let signing_secret = vault.secret_generate(ecdh).unwrap();

        Journal {
            entries: BTreeSet::new(),
            vault,
            encryption_secret,
            signing_secret,
        }
    }
}
const NONCE: &[u8; 12] = b"journal_0123";
const AAD: &[u8; 12] = b"journal_0000";

impl Journal {
    fn encrypt(&mut self, mut entry: Entry) -> Entry {
        let message = entry.message.unwrap();
        let plain = message.as_bytes();

        if let Ok(encrypted) =
            self.vault
                .aead_aes_gcm_encrypt(&self.encryption_secret, plain, NONCE, AAD)
        {
            entry.message = None;
            entry.payload = Some(encrypted);
        } else {
            panic!("Encryption failed!")
        }

        entry
    }

    fn sign(&mut self, mut entry: Entry) -> Entry {
        if let Some(payload) = &entry.payload {
            if let Ok(signature) = self.vault.sign(&self.signing_secret, payload.as_slice()) {
                entry.signature = Some(signature.into());
            } else {
                panic!("Signing failed!")
            }
        } else {
            println!("Ignoring attempt to sign empty payload.")
        }
        entry
    }

    fn add_entry(&mut self, entry: Entry) {
        let entry = self.encrypt(entry);
        let entry = self.sign(entry);

        self.entries.insert(entry);
    }

    fn read(&mut self) {
        let entries = self.entries.clone();
        for entry in &entries {
            println!("Reading entry: {}", entry);
            if entry.is_signed() {
                if self.verify(entry) {
                    println!("✅\tVerified!");
                } else {
                    println!("❌\tVerification failed.")
                }

                if let Some(message) = self.decrypt(entry) {
                    println!("✅\tDecrypted! Message: {}", message);
                } else {
                    println!("❌\tDecryption failed.")
                }
            }
        }
    }

    fn verify(&mut self, entry: &Entry) -> bool {
        let signature = entry.signature.as_ref().unwrap();
        let payload = entry.payload.as_ref().unwrap();

        let sig64 = <&[u8; 64]>::try_from(signature.as_slice()).unwrap();

        let pubkey = self
            .vault
            .secret_public_key_get(&self.signing_secret)
            .unwrap();
        matches!(
            self.vault
                .verify(sig64, pubkey.as_ref(), payload.as_slice()),
            Ok(_)
        )
    }

    fn decrypt(&mut self, entry: &Entry) -> Option<String> {
        let cipher = entry.payload.as_ref().unwrap();
        if let Ok(plain) =
            self.vault
                .aead_aes_gcm_decrypt(&self.encryption_secret, cipher.as_slice(), NONCE, AAD)
        {
            Some(String::from_utf8(plain.to_vec()).unwrap())
        } else {
            None
        }
    }
}

fn main() {
    let mut journal = Journal::default();

    journal.add_entry(Entry::new("my secret"));
    journal.add_entry(Entry::new("another secret"));
    journal.read();
}
