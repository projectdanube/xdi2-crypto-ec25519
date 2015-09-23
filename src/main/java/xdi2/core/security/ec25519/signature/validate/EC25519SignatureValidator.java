package xdi2.core.security.ec25519.signature.validate;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.signature.validate.SignatureValidator;

/**
 * This is a SignatureValidater that can an XDI ECC25519Signature.
 */
public interface EC25519SignatureValidator extends SignatureValidator<EC25519Signature> {

}

