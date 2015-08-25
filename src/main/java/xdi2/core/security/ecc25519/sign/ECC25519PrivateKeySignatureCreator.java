package xdi2.core.security.ecc25519.sign;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jnr.ffi.byref.LongLongByReference;
import xdi2.core.ContextNode;
import xdi2.core.features.signatures.Signatures;
import xdi2.core.features.signatures.ecc25519.ECC25519Signature;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519SignatureCreator that create an XDI ECC25519Signature using a private key,
 * which can be obtained using the XDI address that identifies the signer.
 */
public abstract class ECC25519PrivateKeySignatureCreator extends AbstractECC25519SignatureCreator implements ECC25519SignatureCreator {

	private static Logger log = LoggerFactory.getLogger(ECC25519PrivateKeySignatureCreator.class.getName());

	private String digestAlgorithm;
	private Integer digestLength;

	public ECC25519PrivateKeySignatureCreator() {

	}

	@Override
	public ECC25519Signature create(byte[] normalizedSerialization, ContextNode contextNode, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain private key

		byte[] privateKey = this.getPrivateKey(signerXDIAddress);

		if (privateKey == null) {

			throw new GeneralSecurityException("No private key found for " + signerXDIAddress);
		}

		if (log.isDebugEnabled()) log.debug("Private key found for " + signerXDIAddress + ".");

		// create signature

		ECC25519Signature signature;

		try {

			signature = (ECC25519Signature) Signatures.createSignature(
					contextNode,
					this.getDigestAlgorithm(), 
					this.getDigestLength(), 
					getPrivateKeyAlgorithm(privateKey), 
					getPrivateKeyLength(privateKey), 
					true);
		} catch (Exception ex) {

			throw new GeneralSecurityException("Cannot create signature: " + ex.getMessage(), ex);
		}

		// set signature value

		this.setValue(normalizedSerialization, signature, privateKey);

		// done

		return signature;
	}

	@Override
	public void setValue(byte[] normalizedSerialization, ECC25519Signature signature, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain private key

		byte[] privateKey = this.getPrivateKey(signerXDIAddress);

		if (privateKey == null) {

			throw new GeneralSecurityException("No private key found for " + signerXDIAddress);
		}

		if (log.isDebugEnabled()) log.debug("Private key found for " + signerXDIAddress + ".");

		// set signature value

		this.setValue(normalizedSerialization, signature, privateKey);
	}

	public void setValue(byte[] normalizedSerialization, ECC25519Signature signature, byte[] privateKey) throws GeneralSecurityException {

		// set signature value

		byte[] signatureValue = new byte[Sodium.SIGNATURE_BYTES + normalizedSerialization.length];
		Arrays.fill(signatureValue, 0, Sodium.SIGNATURE_BYTES, (byte) 0);
		System.arraycopy(normalizedSerialization, 0, signatureValue, Sodium.SIGNATURE_BYTES, normalizedSerialization.length);
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519(signatureValue, bufferLen, normalizedSerialization, normalizedSerialization.length, privateKey);
		if (ret != 0) throw new RuntimeException("Crypto error.");

		signatureValue = Arrays.copyOfRange(signatureValue, 0, Sodium.SIGNATURE_BYTES);

		signature.setSignatureValue(signatureValue);
	}

	protected abstract byte[] getPrivateKey(XDIAddress signerXDIAddress) throws GeneralSecurityException;

	/*
	 * Helper methods
	 */

	public static String getPrivateKeyAlgorithm(byte[] privateKey) {

		return ECC25519Signature.KEY_ALGORITHM_ECC25519;
	}

	public static Integer getPrivateKeyLength(byte[] privateKey) {

		return Integer.valueOf(privateKey.length);
	}

	/*
	 * Getters and setters
	 */

	public String getDigestAlgorithm() {

		return this.digestAlgorithm;
	}

	public void setDigestAlgorithm(String digestAlgorithm) {

		this.digestAlgorithm = digestAlgorithm;
	}

	public Integer getDigestLength() {

		return this.digestLength;
	}

	public void setDigestLength(Integer digestLength) {

		this.digestLength = digestLength;
	}
}
