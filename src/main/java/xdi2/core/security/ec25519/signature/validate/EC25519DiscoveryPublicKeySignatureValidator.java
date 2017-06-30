package xdi2.core.security.ec25519.signature.validate;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.client.exceptions.Xdi2ClientException;
import xdi2.core.syntax.XDIAddress;
import xdi2.discovery.XDIDiscoveryClient;
import xdi2.discovery.XDIDiscoveryResult;

/**
 * This is an EC25519PublicKeySignatureValidator that validate an XDI EC25519Signature by
 * obtaining public keys using XDI discovery.
 */
public class EC25519DiscoveryPublicKeySignatureValidator extends EC25519PublicKeySignatureValidator {

	private static Logger log = LoggerFactory.getLogger(EC25519DiscoveryPublicKeySignatureValidator.class.getName());

	public static final XDIDiscoveryClient DEFAULT_DISCOVERY_CLIENT = XDIDiscoveryClient.DEFAULT_DISCOVERY_CLIENT;

	private XDIDiscoveryClient xdiDiscoveryClient;

	public EC25519DiscoveryPublicKeySignatureValidator(XDIDiscoveryClient xdiDiscoveryClient) {

		super();

		this.xdiDiscoveryClient = xdiDiscoveryClient;
	}

	public EC25519DiscoveryPublicKeySignatureValidator() {

		this(DEFAULT_DISCOVERY_CLIENT);
	}

	@Override
	public byte[] getPublicKey(XDIAddress signerXDIAddress) throws GeneralSecurityException {

		// perform discovery

		byte[] publicKey = null;

		try {

			XDIDiscoveryResult xdiDiscoveryResult = this.getXdiDiscoveryClient().discover(signerXDIAddress);

			String publicKeyString = xdiDiscoveryResult.getSignaturePublicKey();
			if (publicKeyString == null) return null;

			publicKey = ec25519PublicKeyFromPublicKeyString(publicKeyString);
		} catch (Xdi2ClientException ex) {

			if (log.isWarnEnabled()) log.warn("Cannot discover public key for " + signerXDIAddress + ": " + ex.getMessage(), ex);

			return null;
		}

		// done

		return publicKey;
	}

	/*
	 * Getters and setters
	 */

	public XDIDiscoveryClient getXdiDiscoveryClient() {

		return this.xdiDiscoveryClient;
	}

	public void setXdiDiscoveryClient(XDIDiscoveryClient xdiDiscoveryClient) {

		this.xdiDiscoveryClient = xdiDiscoveryClient;
	}
}
