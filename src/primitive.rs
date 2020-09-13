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
mod test_crypto_box {
    use crypto_box::{aead::Aead, Box, PublicKey, SecretKey, KEY_SIZE};

    #[test]
    fn encryption_decryption() {
        let mut rng = rand::thread_rng();
        // prepare keys
        // alice
        let alice_secret_key = SecretKey::generate(&mut rng);
        assert_eq!(alice_secret_key.clone().to_bytes().len(), KEY_SIZE);
        let alice_public_key = PublicKey::from(&alice_secret_key);
        let alice_public_key_bytes = alice_secret_key.public_key().as_bytes().clone();
        assert_eq!(
            alice_public_key.as_bytes().clone(),
            alice_public_key_bytes.clone()
        );
        assert_eq!(alice_public_key_bytes.len(), KEY_SIZE);
        // bob
        let bob_secret_key = SecretKey::generate(&mut rng);
        assert_eq!(bob_secret_key.clone().to_bytes().len(), KEY_SIZE);
        let bob_public_key = PublicKey::from(&bob_secret_key);
        let bob_public_key_bytes = bob_public_key.as_bytes().clone();
        assert_eq!(
            bob_public_key.as_bytes().clone(),
            bob_public_key_bytes.clone()
        );
        assert_eq!(bob_public_key_bytes.len(), KEY_SIZE);

        // Alice is encrypting

        // Create a `Box` by performing Diffie-Hellman key agreement between
        // the two keys.
        let alice_box = Box::new(&bob_public_key, &alice_secret_key);
        // Get a random nonce to encrypt the message under
        let nonce = crypto_box::generate_nonce(&mut rng);
        // Message to encrypt
        let plaintext = b"There is our shared bitcoin wallet private key";
        // Encrypt the message using the box
        let ciphertext = alice_box.encrypt(&nonce, &plaintext[..]).unwrap();

        // Bob is decrypting

        // Deserialize Alice's public key from bytes
        let alice_public_key = PublicKey::from(alice_public_key_bytes);
        // Bob can compute the same Box as Alice by performing the reciprocal
        // key exchange operation.
        let bob_box = Box::new(&alice_public_key, &bob_secret_key);
        // Decrypt the message, using the same randomly generated nonce
        let decrypted_plaintext = match bob_box.decrypt(&nonce, &ciphertext[..]) {
            Ok(d) => d,
            Err(e) => format!("{}", e).into(),
        };

        assert_eq!(
            std::str::from_utf8(&plaintext[..]).unwrap(),
            std::str::from_utf8(&decrypted_plaintext[..]).unwrap()
        );
    }
}

#[cfg(test)]
mod test_base58 {}
