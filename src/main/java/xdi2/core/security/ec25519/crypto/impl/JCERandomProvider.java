package xdi2.core.security.ec25519.crypto.impl;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import xdi2.core.security.ec25519.crypto.RandomProvider;

public class JCERandomProvider extends RandomProvider {

	private SecureRandom secureRandom;

	public JCERandomProvider() {

		secureRandom = new SecureRandom();
	}

	@Override
	public byte[] randomBytes(int length) throws GeneralSecurityException {

		return secureRandom.generateSeed(length);
	}
}
