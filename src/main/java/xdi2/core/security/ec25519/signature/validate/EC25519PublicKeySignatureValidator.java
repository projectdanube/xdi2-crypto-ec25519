package xdi2.core.security.ec25519.signature.validate;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.ec25519.crypto.EC25519Provider;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519SignatureValidater that validate an XDI ECC25519Signature using a public key,
 * which can be obtained using the XDI address that identifies the signer.
 */
public abstract class EC25519PublicKeySignatureValidator extends AbstractEC25519SignatureValidator implements EC25519SignatureValidator {

	private static Logger log = LoggerFactory.getLogger(EC25519PublicKeySignatureValidator.class.getName());

	public EC25519PublicKeySignatureValidator() {

	}

	@Override
	public boolean validate(byte[] normalizedSerialization, byte[] signatureValue, EC25519Signature signature, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain public key

		byte[] publicKey = this.getPublicKey(signerXDIAddress);

		if (publicKey == null) {

			if (log.isDebugEnabled()) log.debug("No public key found for " + signerXDIAddress);
			return false;
		}

		if (log.isDebugEnabled()) log.debug("Public key found for " + signerXDIAddress + ": " + new String(Base64.encodeBase64(publicKey), StandardCharsets.UTF_8));

		// validate

		return this.validate(normalizedSerialization, signatureValue, signature, publicKey);
	}

	public boolean validate(byte[] normalizedSerialization, byte[] signatureValue, EC25519Signature signature, byte[] publicKey) throws GeneralSecurityException {

		return EC25519Provider.get().validate(normalizedSerialization, signatureValue, publicKey);
	}

	protected abstract byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException;
}
