#[cfg(test)]
mod test_keys_signing {
    use ed25519_dalek::{Digest, Sha512};
    use ed25519_dalek::{Keypair, PublicKey};
    use ed25519_dalek::{Signature, Signer, Verifier};
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
    use rand::rngs::OsRng;

    #[test]
    fn key_pair_gen_and_size() {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        // get  public from secret
        let public_key = PublicKey::from(&keypair.secret);
        // it must equal to keypair.public
        assert_eq!(keypair.public.to_bytes(), public_key.to_bytes());
        // key sizes
        assert_eq!(keypair.public.to_bytes().len(), PUBLIC_KEY_LENGTH);
        assert_eq!(keypair.secret.to_bytes().len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn signing_verifying() {
        let message: &[u8] = b"This is my bitcoin wallet public key";
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        // sign the message
        let signature: Signature = keypair.sign(message);
        assert_eq!(signature.to_bytes().len(), SIGNATURE_LENGTH);
        // verify the message signature with keypair
        assert!(keypair.verify(message, &signature).is_ok());
        // verify the message with buplic key only (at receiver site)
        let public_key = keypair.public;
        assert!(public_key.verify(message, &signature).is_ok());
        // strict verifying
        assert!(public_key.verify_strict(message, &signature).is_ok());
    }

    #[test]
    fn signing_with_unique_context() {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let message: &[u8] = b"There is my main bitcoin wallet";
        // Create a hash digest object which we'll feed the message into:
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.update(message);
        // add a context for good measure
        let context: &[u8] = b"RotorSigningContext";
        let signature: Signature = keypair.sign_prehashed(prehashed, Some(context)).unwrap();
        // verify the message
        // The sha2::Sha512 struct doesn't implement Copy, so we'll have to create a new one:
        let mut prehashed_again: Sha512 = Sha512::default();
        prehashed_again.update(message);
        let verified = keypair
            .public
            .verify_prehashed(prehashed_again, Some(context), &signature);
        assert!(verified.is_ok());
        // failed verifying without having a context
        let mut prehashed_more: Sha512 = Sha512::default();
        prehashed_more.update(message);
        let verified = keypair
            .public
            .verify_prehashed(prehashed_more, None, &signature);
        assert!(verified.is_err());
    }
}

#[cfg(test)]
mod test_hashing {
    use multihash::{wrap, Blake2b256, Code, Multihash};

    #[test]
    fn test_hashing_blake2b_256() {
        let mh = Blake2b256::digest(b"hello world");
        // valid multihash
        let mh1 = mh.clone();
        // algorithm
        assert_ne!(mh.algorithm(), Code::Sha2_256);
        assert_eq!(mh.algorithm(), Code::Blake2b256);
        let mh2 = Multihash::from_bytes(mh.into_bytes()).unwrap();
        assert_eq!(mh1, mh2);
        // invalid multihash
        assert!(Multihash::from_bytes(vec![1, 2, 3]).is_err());
    }

    #[test]
    fn test_hash_wrapping() {
        let mh = Blake2b256::digest(b"hello world");
        let digest = mh.digest();
        let wrapped: Multihash = wrap(Code::Blake2b256, &digest);
        assert_eq!(wrapped.digest(), digest);
        assert_eq!(wrapped.algorithm(), Code::Blake2b256);
    }
}

#[cfg(test)]
mod test_salsa20 {}

#[cfg(test)]
mod test_crypto_box {}

#[cfg(test)]
mod test_base58 {}
