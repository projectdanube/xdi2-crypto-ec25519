package xdi2.core.security.ec25519.signature.create;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.signature.create.AbstractSignatureCreator;

public abstract class AbstractEC25519SignatureCreator extends AbstractSignatureCreator<EC25519Signature> implements EC25519SignatureCreator {

	protected AbstractEC25519SignatureCreator() {

		super(EC25519Signature.class);
	}
}
