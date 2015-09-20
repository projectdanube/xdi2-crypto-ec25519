package xdi2.core.security.ec25519.sign;

import xdi2.core.features.signatures.EC25519Signature;
import xdi2.core.security.signature.create.SignatureCreator;

/**
 * This is a SignatureCreator that create an XDI ECC25519Signature.
 */
public interface EC25519SignatureCreator extends SignatureCreator<EC25519Signature> {

}
