package xdi2.core.security.ec25519.signature.validate;

import java.security.GeneralSecurityException;

import xdi2.core.security.ec25519.util.EC25519CloudNumberUtil;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519PublicKeySignatureValidater that validate an XDI ECC25519Signature by
 * extracting a public key from an XDI address (cryptographic cloud number).
 */
public class EC25519CloudNumberPublicKeySignatureValidator extends EC25519PublicKeySignatureValidator {

	public EC25519CloudNumberPublicKeySignatureValidator() {

		super();
	}

	@Override
	protected byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// find public key

		CloudNumber signerCloudNumber = CloudNumber.fromXDIAddress(signerXDIAddress);
		if (signerCloudNumber == null) return null;

		byte[] publicKey = EC25519CloudNumberUtil.publicKeyFromEC25519CloudNumber(signerCloudNumber);
		if (publicKey == null) return null;

		// done

		return publicKey;
	}
}
