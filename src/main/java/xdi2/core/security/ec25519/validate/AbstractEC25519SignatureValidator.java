package xdi2.core.security.ec25519.validate;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.validate.AbstractSignatureValidator;

public abstract class AbstractEC25519SignatureValidator extends AbstractSignatureValidator<EC25519Signature> implements EC25519SignatureValidator {

	protected AbstractEC25519SignatureValidator() {

		super(EC25519Signature.class);
	}
}
