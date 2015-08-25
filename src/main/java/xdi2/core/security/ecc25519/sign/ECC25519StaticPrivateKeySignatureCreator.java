package xdi2.core.security.ecc25519.sign;

import java.util.Collections;
import java.util.Map;

import xdi2.core.syntax.XDIAddress;

/**
 * This is an RSAPrivateKeySignatureCreator that create an XDI RSASignature by
 * obtaining private keys from a statically configured list.
 */
public class ECC25519StaticPrivateKeySignatureCreator extends ECC25519PrivateKeySignatureCreator {

	private Map<XDIAddress, byte[]> privateKeys;

	public ECC25519StaticPrivateKeySignatureCreator(Map<XDIAddress, byte[]> privateKeys) {

		super();

		this.privateKeys = privateKeys;
	}

	public ECC25519StaticPrivateKeySignatureCreator(byte[] privateKey) {

		super();

		this.privateKeys = Collections.singletonMap(null, privateKey);
	}

	public ECC25519StaticPrivateKeySignatureCreator() {

		super();
	}

	@Override
	protected byte[] getPrivateKey(XDIAddress signerXDIAddress) {

		// find private key

		byte[] privateKey = this.getPrivateKeys().get(signerXDIAddress);
		if (privateKey == null) return null;

		// done

		return privateKey;
	}

	/*
	 * Getters and setters
	 */

	public Map<XDIAddress, byte[]> getPrivateKeys() {

		return this.privateKeys;
	}

	public void setPrivateKeys(Map<XDIAddress, byte[]> privateKeys) {

		this.privateKeys = privateKeys;
	}

	public byte[] getPrivateKey() {

		return this.privateKeys.get(null);
	}

	public void setPrivateKey(byte[] privateKey) {

		this.privateKeys.put(null, privateKey);
	}
}