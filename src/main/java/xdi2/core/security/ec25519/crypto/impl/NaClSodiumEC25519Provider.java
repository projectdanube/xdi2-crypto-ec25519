package xdi2.core.security.ec25519.crypto.impl;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import jnr.ffi.byref.LongLongByReference;
import xdi2.core.security.ec25519.crypto.EC25519Provider;
import xdi2.core.security.ec25519.crypto.RandomProvider;
import xdi2.core.security.ec25519.crypto.SHA256Provider;

public class NaClSodiumEC25519Provider extends EC25519Provider {

	private Sodium sodium;

	public NaClSodiumEC25519Provider() {

		NaCl.init();
		this.sodium = NaCl.sodium();
	}

	@Override
	public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sodium.PUBLICKEY_BYTES + Sodium.PUBLICKEY_BYTES) throw new GeneralSecurityException("Invalid private key length.");
		if (publicKey.length != Sodium.PUBLICKEY_BYTES) throw new GeneralSecurityException("Invalid public key length.");

		// create seed

		byte[] seed = RandomProvider.get().randomBytes(256);
		seed = SHA256Provider.get().sha256(seed);

		// create key pair

		sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
		System.arraycopy(publicKey, 0, privateKey, Sodium.PUBLICKEY_BYTES, Sodium.PUBLICKEY_BYTES);
	}

	@Override
	public byte[] sign(byte[] message, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sodium.SECRETKEY_BYTES + Sodium.PUBLICKEY_BYTES) throw new GeneralSecurityException("Invalid private key length.");

		byte[] signatureValue = new byte[Sodium.SIGNATURE_BYTES + message.length];
		Arrays.fill(signatureValue, 0, Sodium.SIGNATURE_BYTES, (byte) 0);
		System.arraycopy(message, 0, signatureValue, Sodium.SIGNATURE_BYTES, message.length);

		LongLongByReference bufferLen = new LongLongByReference();

		int ret = sodium.crypto_sign_ed25519(signatureValue, bufferLen, message, message.length, privateKey);
		if (ret != 0) throw new GeneralSecurityException("Signing error.");

		signatureValue = Arrays.copyOfRange(signatureValue, 0, Sodium.SIGNATURE_BYTES);

		return signatureValue;
	}

	@Override
	public boolean validate(byte[] message, byte[] signatureValue, byte[] publicKey) throws GeneralSecurityException {

		if (signatureValue.length != Sodium.SIGNATURE_BYTES) throw new GeneralSecurityException("Invalid signature length.");
		if (publicKey.length != Sodium.PUBLICKEY_BYTES) throw new GeneralSecurityException("Invalid public key length.");

		byte[] sigAndMsg = new byte[signatureValue.length + message.length];
		System.arraycopy(signatureValue, 0, sigAndMsg, 0, signatureValue.length);
		System.arraycopy(message, 0, sigAndMsg, signatureValue.length, message.length);

		byte[] buffer = new byte[sigAndMsg.length];
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519_open(buffer, bufferLen, sigAndMsg, sigAndMsg.length, publicKey);
		if (ret != 0) throw new RuntimeException("Crypto error.");

		buffer = Arrays.copyOf(buffer, buffer.length - Sodium.SIGNATURE_BYTES);

		return Arrays.equals(message, buffer);
	}
}
