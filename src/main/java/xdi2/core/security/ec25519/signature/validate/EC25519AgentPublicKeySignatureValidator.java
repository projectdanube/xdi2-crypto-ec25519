package xdi2.core.security.ec25519.signature.validate;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.agent.XDIAgent;
import xdi2.client.exceptions.Xdi2ClientException;
import xdi2.client.manipulator.impl.SetLinkContractMessageManipulator;
import xdi2.core.ContextNode;
import xdi2.core.constants.XDISecurityConstants;
import xdi2.core.features.linkcontracts.instance.PublicLinkContract;
import xdi2.core.syntax.XDIAddress;
import xdi2.core.util.XDIAddressUtil;

/**
 * This is an EC25519PublicKeySignatureValidator that validate an XDI EC25519Signature by
 * obtaining public keys using an XDI agent.
 */
public class EC25519AgentPublicKeySignatureValidator extends EC25519PublicKeySignatureValidator {

	private static Logger log = LoggerFactory.getLogger(EC25519AgentPublicKeySignatureValidator.class.getName());

	private XDIAgent xdiAgent;

	public EC25519AgentPublicKeySignatureValidator(XDIAgent xdiAgent) {

		super();

		this.xdiAgent = xdiAgent;
	}

	public EC25519AgentPublicKeySignatureValidator() {

		this(null);
	}

	@Override
	public byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// retrieve the key

		byte[] publicKey = null;

		try {

			XDIAddress publicKeyXDIAddress = XDIAddressUtil.concatXDIAddresses(signerXDIAddress, XDISecurityConstants.XDI_ADD_MSG_SIG_KEYPAIR_PUBLIC_KEY);

			ContextNode contextNode = this.getXdiAgent().get(publicKeyXDIAddress, new SetLinkContractMessageManipulator(PublicLinkContract.class));
			if (contextNode == null) return null;

			String publicKeyString = contextNode.getLiteralDataString();
			if (publicKeyString == null) return null;

			publicKey = ec25519PublicKeyFromPublicKeyString(publicKeyString);
		} catch (Xdi2ClientException ex) {

			if (log.isWarnEnabled()) log.warn("Cannot retrieve public key for " + signerXDIAddress + ": " + ex.getMessage(), ex);
			return null;
		}

		// done

		return publicKey;
	}

	/*
	 * Getters and setters
	 */

	public XDIAgent getXdiAgent() {

		return this.xdiAgent;
	}

	public void setXdiAgent(XDIAgent xdiAgent) {

		this.xdiAgent = xdiAgent;
	}
}
