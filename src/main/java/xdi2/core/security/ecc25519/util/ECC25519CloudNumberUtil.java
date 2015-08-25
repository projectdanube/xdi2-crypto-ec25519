package xdi2.core.security.ecc25519.util;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import xdi2.core.constants.XDIConstants;
import xdi2.core.syntax.CloudNumber;

public class ECC25519CloudNumberUtil {

	public static final String XDI_SCHEME_ECC25519 = ":publickey-curve25519-base58-check:";
	public static final byte XDI_APPCODE_ECC25519 = 0x00;

	public static CloudNumber createECC25519CloudNumber(Character cs, byte[] pub) throws Exception {

		String string = cs.charValue() + XDIConstants.S_IMMUTABLE.charValue() + XDI_SCHEME_ECC25519 + base58WithAppCodeAndChecksum(pub);

		return CloudNumber.create(string);
	}

	public static boolean isECC25519CloudNumber(CloudNumber cloudNumber) {

		return cloudNumber.toString().startsWith(cloudNumber.getXDIAddress().getFirstXDIArc().getCs().charValue() + XDIConstants.S_IMMUTABLE.charValue() + XDI_SCHEME_ECC25519);
	}

	public static byte[] publicKeyFromECC25519CloudNumber(CloudNumber cloudNumber) throws GeneralSecurityException {

		if (cloudNumber == null) throw new NullPointerException();
		if (! isECC25519CloudNumber(cloudNumber)) return null;

		String string = cloudNumber.toString().substring(2 + XDI_SCHEME_ECC25519.length());
		byte[] bytes = Base58.decode(string);

		if (! appCodeCorrect(bytes)) throw new GeneralSecurityException("App code invalid for ECC25519 cloud number: " + cloudNumber);
		if (! checksumCorrect(bytes)) throw new GeneralSecurityException("Checksum invalid for ECC25519 cloud number: " + cloudNumber);

		return Arrays.copyOfRange(bytes, 1, bytes.length - 4);
	}

	private static byte[] checksum(byte[] bytesAppCodeAndKey) throws GeneralSecurityException {

		return SHA256.sha256(SHA256.sha256(bytesAppCodeAndKey));
	}

	private static boolean appCodeCorrect(byte[] bytes) {

		return bytes[0] == XDI_APPCODE_ECC25519;
	}

	private static boolean checksumCorrect(byte[] bytes) throws GeneralSecurityException {

		byte[] bytesAppCodeAndKey = new byte[33];
		System.arraycopy(bytes, 0, bytesAppCodeAndKey, 0, 33);

		byte[] bytesChecksum = new byte[4];
		System.arraycopy(bytes, 33, bytesChecksum, 0, 4);

		return Arrays.equals(bytesChecksum, checksum(bytesAppCodeAndKey));
	}

	private static String base58WithAppCodeAndChecksum(byte[] key) throws GeneralSecurityException {

		byte[] bytesAppCodeAndKey = new byte[33];
		bytesAppCodeAndKey[0] = XDI_APPCODE_ECC25519;
		System.arraycopy(key, 0, bytesAppCodeAndKey, 1, 32);

		byte[] bytesChecksum = checksum(bytesAppCodeAndKey);

		byte[] bytes = new byte[37];
		System.arraycopy(bytesAppCodeAndKey, 0, bytes, 0, 33);
		System.arraycopy(bytesChecksum, 0, bytes, 33, 4);

		return Base58.encode(bytes);
	}
}
