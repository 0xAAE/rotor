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
    use multihash::{Code, Multihash, MultihashDigest, U64};

    #[test]
    fn test_hashing_blake2b_256() {
        let hash = Code::Blake2b256.digest(b"hello world");
        // valid multihash
        let mh1 = hash.clone();
        let mh2 = Multihash::from_bytes(&hash.to_bytes()).unwrap();
        assert_eq!(mh1, mh2);
        // invalid multihash
        assert!(Multihash::<U64>::from_bytes(&vec![1, 2, 3]).is_err());
    }

    #[test]
    fn test_hash_wrapping() {
        let hash = Code::Blake2b256.digest(b"hello world");
        assert_eq!(hash.code(), Code::Blake2b256.into());
        let wrapped = Multihash::wrap(Code::Blake2b256.into(), &hash.digest()).unwrap();
        assert_eq!(wrapped, hash);
        assert_eq!(wrapped.code(), Code::Blake2b256.into());
    }
}

#[cfg(test)]
mod test_salsa20 {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use salsa20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use salsa20::{Key, Nonce, Salsa20};

    #[test]
    fn test_encrypting() {
        assert_eq!(ed25519_dalek::SECRET_KEY_LENGTH, salsa20::KEY_SIZE);
        let mut data = [1, 2, 3, 4, 5, 6, 7];

        let key = Key::from_slice(b"an example very very secret key.");
        let nonce = Nonce::from_slice(b"a nonce.");

        // create cipher instance
        let mut cipher = Salsa20::new(&key, &nonce);

        // apply keystream (encrypt)
        cipher.apply_keystream(&mut data);
        assert_eq!(data, [182, 14, 133, 113, 210, 25, 165]);

        // seek to the keystream beginning and apply it again to the `data` (decrypt)
        cipher.seek(0);
        cipher.apply_keystream(&mut data);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
    }

    const SALSA_NONCE_SIZE: usize = 8;

    #[test]
    fn test_encrypting_with_ed25519_keys() {
        let src = b"Me main bitcoin wallet key";
        let mut data = src.clone();

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let key = Key::from_slice(keypair.secret.as_bytes());
        let nonce = Nonce::from_slice(&keypair.public.as_bytes()[..SALSA_NONCE_SIZE]);

        // create cipher instance
        let mut cipher = Salsa20::new(&key, &nonce);

        // apply keystream (encrypt)
        cipher.apply_keystream(&mut data);
        // seek to the keystream beginning and apply it again to the `data` (decrypt)
        cipher.seek(0);
        cipher.apply_keystream(&mut data);
        assert_eq!(data, src.clone());
    }
}

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
mod test_base58 {
    use bs58::{decode, encode};
    use ed25519_dalek::Keypair;

    #[test]
    fn test_base58() {
        let mut rng = rand::thread_rng();
        let keypair: Keypair = Keypair::generate(&mut rng);

        let encoded = encode(keypair.public.as_bytes()).into_string();
        let decoded = decode(encoded).into_vec().unwrap();
        assert_eq!(decoded, keypair.public.as_bytes());
    }
}

#[cfg(test)]
mod test_mixed {
    use ed25519_dalek::Keypair;
    use salsa20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use salsa20::{Key, XSalsa20};

    #[test]
    fn test_encrypting_with_ed25519_keys() {
        let src = b"Me main bitcoin wallet key";
        let mut data = src.clone();

        let mut rng = rand::thread_rng();
        let keypair: Keypair = Keypair::generate(&mut rng);

        let key = Key::from_slice(keypair.secret.as_bytes());
        let nonce = crypto_box::generate_nonce(&mut rng);

        // create cipher instance
        let mut cipher = XSalsa20::new(&key, &nonce);

        // apply keystream (encrypt)
        cipher.apply_keystream(&mut data);
        // seek to the keystream beginning and apply it again to the `data` (decrypt)
        cipher.seek(0);
        cipher.apply_keystream(&mut data);
        assert_eq!(data, src.clone());
    }
}
