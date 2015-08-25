package xdi2.core.security.ec25519.validate;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.validate.SignatureValidator;

/**
 * This is a SignatureValidater that can an XDI ECC25519Signature.
 */
public interface EC25519SignatureValidator extends SignatureValidator<EC25519Signature> {

}

