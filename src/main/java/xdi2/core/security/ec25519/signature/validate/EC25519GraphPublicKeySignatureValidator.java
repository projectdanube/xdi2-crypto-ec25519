package xdi2.core.security.ec25519.signature.validate;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.core.Graph;
import xdi2.core.features.keys.Keys;
import xdi2.core.features.nodetypes.XdiCommonRoot;
import xdi2.core.features.nodetypes.XdiEntity;
import xdi2.core.syntax.XDIAddress;
import xdi2.core.util.GraphUtil;

/**
 * This is an EC25519PublicKeySignatureValidator that can validate an XDI EC25519Signature by
 * obtaining public keys from a "public key graph".
 */
public class EC25519GraphPublicKeySignatureValidator extends EC25519PublicKeySignatureValidator {

	private static Logger log = LoggerFactory.getLogger(EC25519GraphPublicKeySignatureValidator.class.getName());

	private Graph publicKeyGraph;

	public EC25519GraphPublicKeySignatureValidator(Graph publicKeyGraph) {

		super();

		this.publicKeyGraph = publicKeyGraph;
	}

	public EC25519GraphPublicKeySignatureValidator() {

		super();

		this.publicKeyGraph = null;
	}

	@Override
	public byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// signer address

		if (signerXDIAddress == null) {

			signerXDIAddress = GraphUtil.getOwnerXDIAddress(this.getPublicKeyGraph());
		}

		// signer entity

		XdiEntity signerXdiEntity = XdiCommonRoot.findCommonRoot(this.getPublicKeyGraph()).getXdiEntity(signerXDIAddress, false);
		signerXdiEntity = signerXdiEntity == null ? null : signerXdiEntity.dereference();

		if (log.isDebugEnabled()) log.debug("Signer entity: " + signerXdiEntity + " in graph " + GraphUtil.getOwnerPeerRootXDIArc(this.getPublicKeyGraph()));
		if (signerXdiEntity == null) return null;

		// find public key

		byte[] publicKey = ec25519PublicKeyFromPublicKeyString(Keys.getSignaturePublicKey(signerXdiEntity));

		// done

		return publicKey;
	}

	/*
	 * Getters and setters
	 */

	public Graph getPublicKeyGraph() {

		return this.publicKeyGraph;
	}

	public void setPublicKeyGraph(Graph publicKeyGraph) {

		this.publicKeyGraph = publicKeyGraph;
	}
}
