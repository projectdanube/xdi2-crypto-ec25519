package xdi2.core.security.ec25519.crypto.impl;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import xdi2.core.security.ec25519.crypto.SHA256Provider;

public class JCESHA256Provider extends SHA256Provider {

	@Override
	public byte[] sha256(byte[] bytes) throws GeneralSecurityException {

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(bytes);

		return digest.digest();
	}
}
