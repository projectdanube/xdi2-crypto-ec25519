package xdi2.core.security.ec25519.sign;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.core.ContextNode;
import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.features.signatures.Signature;
import xdi2.core.features.signatures.Signatures;
import xdi2.core.security.ec25519.crypto.EC25519Provider;
import xdi2.core.syntax.XDIAddress;

/**
 * This is an ECC25519SignatureCreator that create an XDI ECC25519Signature using a private key,
 * which can be obtained using the XDI address that identifies the signer.
 */
public abstract class EC25519PrivateKeySignatureCreator extends AbstractEC25519SignatureCreator implements EC25519SignatureCreator {

	private static Logger log = LoggerFactory.getLogger(EC25519PrivateKeySignatureCreator.class.getName());

	private String digestAlgorithm;
	private Integer digestLength;

	public EC25519PrivateKeySignatureCreator() {

	}

	@Override
	public EC25519Signature create(byte[] normalizedSerialization, ContextNode contextNode, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain private key

		byte[] privateKey = this.getPrivateKey(signerXDIAddress);

		if (privateKey == null) {

			if (log.isDebugEnabled()) log.debug("No private key found for " + signerXDIAddress);
			return null;
		}

		if (log.isDebugEnabled()) log.debug("Private key found for " + signerXDIAddress + ".");

		// create signature

		EC25519Signature signature;

		try {

			signature = (EC25519Signature) Signatures.createSignature(
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
	public void setValue(byte[] normalizedSerialization, EC25519Signature signature, XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// obtain private key

		byte[] privateKey = this.getPrivateKey(signerXDIAddress);

		if (privateKey == null) {

			throw new GeneralSecurityException("No private key found for " + signerXDIAddress);
		}

		if (log.isDebugEnabled()) log.debug("Private key found for " + signerXDIAddress + ".");

		// set signature value

		this.setValue(normalizedSerialization, signature, privateKey);
	}

	public void setValue(byte[] normalizedSerialization, Signature signature, byte[] privateKey) throws GeneralSecurityException {

		// set signature value

		byte[] signatureValue = EC25519Provider.get().sign(normalizedSerialization, privateKey);

		signature.setSignatureValue(signatureValue);
	}

	protected abstract byte[] getPrivateKey(XDIAddress signerXDIAddress) throws GeneralSecurityException;

	/*
	 * Helper methods
	 */

	public static String getPrivateKeyAlgorithm(byte[] privateKey) {

		return EC25519Signature.KEY_ALGORITHM_EC25519;
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
