package xdi2.core.security.ecc25519.validate;

import xdi2.core.features.signatures.ecc25519.ECC25519Signature;
import xdi2.core.security.validate.AbstractSignatureValidator;
import xdi2.core.security.validate.SignatureValidator;

public abstract class AbstractECC25519SignatureValidator extends AbstractSignatureValidator<ECC25519Signature> implements SignatureValidator<ECC25519Signature> {

}
