package xdi2.core.security.ecc25519.validate;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jnr.ffi.byref.LongLongByReference;
import xdi2.core.features.signatures.ecc25519.ECC25519Signature;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519SignatureValidater that validate an XDI ECC25519Signature using a public key,
 * which can be obtained using the XDI address that identifies the signer.
 */
public abstract class ECC25519PublicKeySignatureValidator extends AbstractECC25519SignatureValidator implements ECC25519SignatureValidator {

	private static Logger log = LoggerFactory.getLogger(ECC25519PublicKeySignatureValidator.class.getName());

	public ECC25519PublicKeySignatureValidator() {

	}

	@Override
	public boolean validate(byte[] normalizedSerialization, byte[] signatureValue, ECC25519Signature signature, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain public key

		byte[] publicKey = this.getPublicKey(signerXDIAddress);

		if (publicKey == null) {

			if (log.isDebugEnabled()) log.debug("No public key found for " + signerXDIAddress);

			return false;
		}

		if (log.isDebugEnabled()) log.debug("Public key found for " + signerXDIAddress + ": " + new String(Base64.encodeBase64(publicKey), Charset.forName("UTF-8")));

		// validate

		return this.validate(normalizedSerialization, signatureValue, signature, publicKey);
	}

	public boolean validate(byte[] normalizedSerialization, byte[] signatureValue, ECC25519Signature signature, byte[] publicKey) throws GeneralSecurityException {

		byte[] sigAndMsg = new byte[signatureValue.length + normalizedSerialization.length];
		System.arraycopy(signatureValue, 0, sigAndMsg, 0, signatureValue.length);
		System.arraycopy(normalizedSerialization, 0, sigAndMsg, signatureValue.length, normalizedSerialization.length);

		byte[] buffer = new byte[sigAndMsg.length];
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519_open(buffer, bufferLen, sigAndMsg, sigAndMsg.length, publicKey);
		if (ret != 0) throw new RuntimeException("Crypto error.");

		buffer = Arrays.copyOf(buffer, buffer.length - Sodium.SIGNATURE_BYTES);

		return Arrays.equals(normalizedSerialization, buffer);
	}

	protected abstract byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException;
}
