package xdi2.core.security.ecc25519.validate;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;

import xdi2.core.security.ecc25519.util.ECC25519CloudNumberUtil;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519PublicKeySignatureValidater that validate an XDI ECC25519Signature by
 * obtaining public keys from a statically configured list.
 */
public class ECC25519CloudNumberPublicKeySignatureValidator extends ECC25519PublicKeySignatureValidator {

	private Map<XDIAddress, byte[]> publicKeys;

	public ECC25519CloudNumberPublicKeySignatureValidator(Map<XDIAddress, byte[]> publicKeys) {

		super();

		this.publicKeys = publicKeys;
	}

	public ECC25519CloudNumberPublicKeySignatureValidator(byte[] publicKey) {

		super();

		this.publicKeys = Collections.singletonMap(null, publicKey);
	}

	public ECC25519CloudNumberPublicKeySignatureValidator() {

		super();
	}

	@Override
	protected byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// find public key

		CloudNumber signerCloudNumber = CloudNumber.fromXDIAddress(signerXDIAddress);
		if (signerCloudNumber == null) return null;

		byte[] publicKey = ECC25519CloudNumberUtil.publicKeyFromECC25519CloudNumber(signerCloudNumber);
		if (publicKey == null) return null;

		// done

		return publicKey;
	}

	public Map<XDIAddress, byte[]> getPublicKeys() {

		return this.publicKeys;
	}

	public void setPublicKeys(Map<XDIAddress, byte[]> publicKeys) {

		this.publicKeys = publicKeys;
	}

	public byte[] getPublicKey() {

		return this.publicKeys.get(null);
	}

	public void setPublicKey(byte[] publicKey) {

		this.publicKeys.put(null, publicKey);
	}
}
