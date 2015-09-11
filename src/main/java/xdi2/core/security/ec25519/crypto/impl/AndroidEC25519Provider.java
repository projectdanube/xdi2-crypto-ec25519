package xdi2.core.security.ec25519.crypto.impl;

import java.security.GeneralSecurityException;

import com.github.dazoe.android.Ed25519;

import xdi2.core.security.ec25519.crypto.EC25519Provider;
import xdi2.core.security.ec25519.crypto.RandomProvider;
import xdi2.core.security.ec25519.crypto.SHA256Provider;

public class AndroidEC25519Provider extends EC25519Provider {

	@Override
	public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {

		// create seed

		byte[] seed = RandomProvider.get().randomBytes(256);
		seed = SHA256Provider.get().sha256(seed);

		// create private key

		System.arraycopy(seed, 0, privateKey, 0, 32);

		// create public key

		try {

			System.arraycopy(Ed25519.ExpandPrivateKey(privateKey), 32, publicKey, 0, 32);
		} catch (Exception ex) {

			throw new GeneralSecurityException(ex.getMessage(), ex);
		}

		assert(publicKey.length == 32);
		assert(privateKey.length == 32);
	}

	@Override
	public byte[] sign(byte[] message, byte[] privateKey) throws GeneralSecurityException {

		try {

			return Ed25519.Sign(message, privateKey);
		} catch (Exception ex) {

			throw new GeneralSecurityException(ex.getMessage(), ex);
		}
	}

	@Override
	public boolean validate(byte[] message, byte[] signatureValue, byte[] publicKey) throws GeneralSecurityException {

		try {

			return Ed25519.Verify(message, signatureValue, publicKey) == 0;
		} catch (Exception ex) {

			throw new GeneralSecurityException(ex.getMessage(), ex);
		}
	}
}
