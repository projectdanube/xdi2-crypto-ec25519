package xdi2.core.security.ec25519.crypto.impl;

import java.security.GeneralSecurityException;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import xdi2.core.security.ec25519.crypto.RandomProvider;

public class NaClSodiumRandomProvider extends RandomProvider {

	private Sodium sodium;

	public NaClSodiumRandomProvider() {

		NaCl.init();
		this.sodium = NaCl.sodium();
	}

	@Override
	public byte[] randomBytes(int length) throws GeneralSecurityException {

		byte[] randomBytes = new byte[length];
		sodium.randombytes(randomBytes, 256);

		return randomBytes;
	}
}
