package xdi2.core.security.ec25519.signature.create;

import java.util.Collections;
import java.util.Map;

import xdi2.core.syntax.XDIAddress;

/**
 * This is an RSAPrivateKeySignatureCreator that create an XDI RSASignature by
 * obtaining private keys from a statically configured list.
 */
public class EC25519StaticPrivateKeySignatureCreator extends EC25519PrivateKeySignatureCreator {

	private Map<XDIAddress, byte[]> privateKeys;

	public EC25519StaticPrivateKeySignatureCreator(Map<XDIAddress, byte[]> privateKeys) {

		super();

		this.privateKeys = privateKeys;
	}

	public EC25519StaticPrivateKeySignatureCreator(byte[] privateKey) {

		super();

		this.privateKeys = Collections.singletonMap(null, privateKey);
	}

	public EC25519StaticPrivateKeySignatureCreator() {

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