package xdi2.core.features.signatures.ecc25519;

import java.security.GeneralSecurityException;

import xdi2.core.constants.XDIAuthenticationConstants;
import xdi2.core.features.nodetypes.XdiAbstractContext;
import xdi2.core.features.nodetypes.XdiAttribute;
import xdi2.core.features.nodetypes.XdiAttributeInstance;
import xdi2.core.features.nodetypes.XdiAttributeSingleton;
import xdi2.core.features.signatures.Signature;
import xdi2.core.features.signatures.Signatures;
import xdi2.core.security.ecc25519.sign.ECC25519PrivateKeySignatureCreator;
import xdi2.core.security.ecc25519.sign.ECC25519StaticPrivateKeySignatureCreator;
import xdi2.core.security.ecc25519.validate.ECC25519PublicKeySignatureValidator;
import xdi2.core.security.ecc25519.validate.ECC25519CloudNumberPublicKeySignatureValidator;

/**
 * An XDI signature, represented as an XDI attribute.
 * 
 * @author markus
 */
public final class ECC25519Signature extends Signature {

	private static final long serialVersionUID = -5809066928136679213L;

	public static final String KEY_ALGORITHM_ECC25519 = "ecc25519";

	public static final String DIGEST_ALGORITHM_SHA = "sha";

	protected ECC25519Signature(XdiAttribute xdiAttribute) {

		super(xdiAttribute);
	}

	/*
	 * Static methods
	 */

	/**
	 * Checks if an XDI attribute is a valid XDI signature.
	 * @param xdiAttribute The XDI attribute to check.
	 * @return True if the XDI attribute is a valid XDI signature.
	 */
	public static boolean isValid(XdiAttribute xdiAttribute) {

		if (xdiAttribute instanceof XdiAttributeSingleton) {

			if (! ((XdiAttributeSingleton) xdiAttribute).getBaseXDIArc().equals(XdiAbstractContext.getBaseXDIArc(XDIAuthenticationConstants.XDI_ARC_SIGNATURE))) return false;
		} else if (xdiAttribute instanceof XdiAttributeInstance) {

			if (! ((XdiAttributeInstance) xdiAttribute).getXdiCollection().getBaseXDIArc().equals(XdiAbstractContext.getBaseXDIArc(XDIAuthenticationConstants.XDI_ARC_SIGNATURE))) return false;
		} else {

			return false;
		}

		String keyAlgorithm = Signatures.getKeyAlgorithm(xdiAttribute);
		String digestAlgorithm = Signatures.getDigestAlgorithm(xdiAttribute);

		if (! KEY_ALGORITHM_ECC25519.equalsIgnoreCase(keyAlgorithm)) return false;
		if (! DIGEST_ALGORITHM_SHA.equalsIgnoreCase(digestAlgorithm)) return false;

		return true;
	}

	/**
	 * Factory method that creates an XDI signature bound to a given XDI attribute.
	 * @param xdiAttribute The XDI attribute that is an XDI signature.
	 * @return The XDI signature.
	 */
	public static ECC25519Signature fromXdiAttribute(XdiAttribute xdiAttribute) {

		if (! isValid(xdiAttribute)) return null;

		return new ECC25519Signature(xdiAttribute);
	}

	/*
	 * Instance methods
	 */

	@Override
	public String getAlgorithm() {

		StringBuilder builder = new StringBuilder();

		builder.append(this.getDigestAlgorithm().toUpperCase());
		builder.append(this.getDigestLength());
		builder.append("with");
		builder.append(this.getKeyAlgorithm().toUpperCase());

		return builder.toString();
	}

	public void createSignature(byte[] privateKey) throws GeneralSecurityException {

		ECC25519PrivateKeySignatureCreator signatureCreator = new ECC25519StaticPrivateKeySignatureCreator(privateKey);

		signatureCreator.createSignature(this);
	}

	public boolean validateSignature(byte[] publicKey) throws GeneralSecurityException {

		ECC25519PublicKeySignatureValidator signatureValidator = new ECC25519CloudNumberPublicKeySignatureValidator(publicKey);

		return signatureValidator.validateSignature(this);
	}
}
