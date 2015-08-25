package xdi2.core.security.ecc25519.sign;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.core.Graph;
import xdi2.core.features.nodetypes.XdiCommonRoot;
import xdi2.core.features.nodetypes.XdiEntity;
import xdi2.core.syntax.XDIAddress;
import xdi2.core.util.GraphAware;
import xdi2.core.util.GraphUtil;

/**
 * This is an ECC25519PrivateKeySignatureCreator that create an XDI ECC25519Signature by
 * obtaining private keys from a "private key graph".
 */
public class ECC25519GraphPrivateKeySignatureCreator extends ECC25519PrivateKeySignatureCreator implements GraphAware {

	private static Logger log = LoggerFactory.getLogger(ECC25519GraphPrivateKeySignatureCreator.class.getName());

	private Graph privateKeyGraph;

	public ECC25519GraphPrivateKeySignatureCreator(Graph privateKeyGraph) {

		super();

		this.privateKeyGraph = privateKeyGraph;
	}

	public ECC25519GraphPrivateKeySignatureCreator() {

		super();

		this.privateKeyGraph = null;
	}

	@Override
	public byte[] getPrivateKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// signer address

		if (signerXDIAddress == null) {

			signerXDIAddress = GraphUtil.getOwnerXDIAddress(this.getPrivateKeyGraph());
		}

		// signer entity

		XdiEntity signerXdiEntity = XdiCommonRoot.findCommonRoot(this.getPrivateKeyGraph()).getXdiEntity(signerXDIAddress, false);
		signerXdiEntity = signerXdiEntity == null ? null : signerXdiEntity.dereference();

		if (log.isDebugEnabled()) log.debug("Signer entity: " + signerXdiEntity);

		if (signerXdiEntity == null) return null;

		// find private key

		byte[] privateKey = null;// TODO!Keys.getSignaturePrivateKey(signerXdiEntity);

		// done

		return privateKey;
	}

	/*
	 * GraphAware
	 */

	@Override
	public void setGraph(Graph graph) {

		if (this.getPrivateKeyGraph() == null) this.setPrivateKeyGraph(graph);
	}

	/*
	 * Getters and setters
	 */

	public Graph getPrivateKeyGraph() {

		return this.privateKeyGraph;
	}

	public void setPrivateKeyGraph(Graph privateKeyGraph) {

		this.privateKeyGraph = privateKeyGraph;
	}
}
