use super::*;
use bbs::prelude::{
    DeterministicPublicKey, Issuer as BbsIssuer, KeyGenOption, ProofNonce, RandomElem, SecretKey,
};
use ockam_core::lib::*;
use pairing_plus::{
    bls12_381::{Fr, G1},
    hash_to_curve::HashToCurve,
    hash_to_field::ExpandMsgXmd,
    serdes::SerDes,
    CurveProjective,
};

pub(crate) const CSUITE_POP: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Represents an issuer of a credential
#[derive(Debug)]
pub struct Issuer {
    signing_key: SecretKey,
}

impl Issuer {
    /// Create issuer with a new issuing key
    pub fn new() -> Self {
        Self {
            signing_key: SecretKey::random(),
        }
    }

    /// Return the signing key associated with this Issuer
    pub fn get_signing_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes_compressed_form()
    }

    /// Return the public key
    pub fn get_public_key(&self) -> [u8; 96] {
        let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(
            self.signing_key.clone(),
        )));
        dpk.to_bytes_compressed_form()
    }

    /// Initialize an issuer with an already generated key
    pub fn with_signing_key(signing_key: SecretKey) -> Self {
        Self { signing_key }
    }

    /// Create a credential offer
    pub fn create_offer(&self, schema: &CredentialSchema) -> CredentialOffer {
        let id = BbsIssuer::generate_signing_nonce().to_bytes_compressed_form();
        CredentialOffer {
            id,
            schema: schema.clone(),
        }
    }

    /// Create a proof of possession for this issuers signing key
    pub fn create_proof_of_possession(&self) -> [u8; 48] {
        let mut p = <G1 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &self.get_public_key(),
            CSUITE_POP,
        );

        let mut c = std::io::Cursor::new(self.signing_key.to_bytes_compressed_form());
        let fr = Fr::deserialize(&mut c, true).unwrap();
        p.mul_assign(fr);
        let mut s = [0u8; 48];
        let _ = p.serialize(&mut s.as_mut(), true);
        s
    }

    /// Sign the claims into the credential
    pub fn sign_credential(
        &self,
        schema: &CredentialSchema,
        attributes: &[CredentialAttribute],
    ) -> Result<Credential, CredentialError> {
        if schema.attributes.len() != attributes.len() {
            return Err(CredentialError::MismatchedAttributesAndClaims);
        }
        let mut messages = Vec::new();
        for (att, v) in schema.attributes.iter().zip(attributes) {
            match (att.attribute_type, v) {
                (CredentialAttributeType::Blob, CredentialAttribute::Blob(_)) => {
                    messages.push(v.to_signature_message())
                }
                (CredentialAttributeType::Utf8String, CredentialAttribute::String(_)) => {
                    messages.push(v.to_signature_message())
                }
                (CredentialAttributeType::Number, CredentialAttribute::Numeric(_)) => {
                    messages.push(v.to_signature_message())
                }
                (_, CredentialAttribute::NotSpecified) => messages.push(v.to_signature_message()),
                (_, CredentialAttribute::Empty) => messages.push(v.to_signature_message()),
                (_, _) => return Err(CredentialError::MismatchedAttributeClaimType),
            }
        }

        let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(
            self.signing_key.clone(),
        )));
        let pk = dpk
            .to_public_key(schema.attributes.len())
            .map_err(|_| CredentialError::MismatchedAttributesAndClaims)?;
        let signature = BbsIssuer::sign(messages.as_slice(), &self.signing_key, &pk)
            .map_err(|_| CredentialError::MismatchedAttributesAndClaims)?;
        Ok(Credential {
            attributes: attributes.to_vec(),
            signature,
        })
    }

    /// Blind sign assumes certain claims have already been committed and signs the remaining claims
    pub fn blind_sign_credential(
        &self,
        ctx: &CredentialRequest,
        schema: &CredentialSchema,
        attributes: &BTreeMap<String, CredentialAttribute>,
        nonce: [u8; 32],
    ) -> Result<BlindCredential, CredentialError> {
        if attributes.len() >= schema.attributes.len() {
            return Err(CredentialError::MismatchedAttributesAndClaims);
        }
        let atts = schema
            .attributes
            .iter()
            .enumerate()
            .map(|(i, a)| (a.label.clone(), (i, a.clone())))
            .collect::<BTreeMap<String, (usize, CredentialAttributeSchema)>>();
        let mut messages = BTreeMap::new();

        let mut blind_atts = BTreeMap::new();
        for (label, data) in attributes {
            let (i, a) = atts
                .get(label)
                .ok_or(CredentialError::InvalidCredentialAttribute)?;
            if *data != a.attribute_type {
                return Err(CredentialError::MismatchedAttributeClaimType);
            }
            blind_atts.insert(*i, data.clone());
            messages.insert(*i, data.to_signature_message());
        }
        let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(
            self.signing_key.clone(),
        )));
        let pk = dpk
            .to_public_key(schema.attributes.len())
            .map_err(|_| CredentialError::MismatchedAttributesAndClaims)?;

        let signature = BbsIssuer::blind_sign(
            &ctx.context,
            &messages,
            &self.signing_key,
            &pk,
            &ProofNonce::from(nonce),
        )
        .map_err(|_| CredentialError::InvalidCredentialAttribute)?;

        Ok(BlindCredential {
            attributes: blind_atts.iter().map(|(_, v)| v.clone()).collect(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_proof_of_possession_test() {
        let issuer = Issuer::new();

        let proof = issuer.create_proof_of_possession();

        let mut t = 0u8;
        for b in &proof {
            t |= *b;
        }
        assert!(t > 0);
    }
}
