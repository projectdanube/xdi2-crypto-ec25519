package xdi2.core.security.ec25519.util;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class SHA256 {

	static byte[] sha256(byte[] bytes) throws GeneralSecurityException {

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(bytes);
		return digest.digest();
	}
}
