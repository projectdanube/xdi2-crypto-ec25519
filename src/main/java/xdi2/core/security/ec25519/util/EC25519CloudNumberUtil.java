package xdi2.core.security.ec25519.util;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import xdi2.core.constants.XDIConstants;
import xdi2.core.security.ec25519.constants.EC25519Constants;
import xdi2.core.security.ec25519.crypto.SHA256Provider;
import xdi2.core.syntax.CloudNumber;

public class EC25519CloudNumberUtil {

	public static CloudNumber createEC25519CloudNumber(Character cs, byte[] pub) throws GeneralSecurityException {

		StringBuffer buffer = new StringBuffer();
		buffer.append(cs.charValue());
		buffer.append(XDIConstants.S_IMMUTABLE.toString());
		buffer.append(EC25519Constants.XDI_SCHEME_EC25519);
		buffer.append(base58WithAppCodeAndChecksum(pub));

		return CloudNumber.create(buffer.toString());
	}

	public static boolean isEC25519CloudNumber(CloudNumber cloudNumber) {

		return cloudNumber.toString().startsWith(cloudNumber.getXDIAddress().getFirstXDIArc().getCs().charValue() + XDIConstants.S_IMMUTABLE.toString() + EC25519Constants.XDI_SCHEME_EC25519);
	}

	public static byte[] publicKeyFromEC25519CloudNumber(CloudNumber cloudNumber) throws GeneralSecurityException {

		if (cloudNumber == null) throw new NullPointerException();
		if (! isEC25519CloudNumber(cloudNumber)) return null;

		String string = cloudNumber.toString().substring(2 + EC25519Constants.XDI_SCHEME_EC25519.length());
		byte[] bytes = Base58.decode(string);

		if (! appCodeCorrect(bytes)) throw new GeneralSecurityException("App code invalid for EC25519 cloud number: " + cloudNumber);
		if (! checksumCorrect(bytes)) throw new GeneralSecurityException("Checksum invalid for EC25519 cloud number: " + cloudNumber);

		return Arrays.copyOfRange(bytes, 1, bytes.length - 4);
	}

	private static boolean appCodeCorrect(byte[] bytes) {

		return bytes[0] == EC25519Constants.XDI_APPCODE_EC25519;
	}

	private static boolean checksumCorrect(byte[] bytes) throws GeneralSecurityException {

		byte[] bytesAppCodeAndKey = new byte[33];
		System.arraycopy(bytes, 0, bytesAppCodeAndKey, 0, 33);

		byte[] bytesChecksum = new byte[4];
		System.arraycopy(bytes, 33, bytesChecksum, 0, 4);

		return Arrays.equals(bytesChecksum, checksum(bytesAppCodeAndKey));
	}

	private static byte[] checksum(byte[] bytesAppCodeAndKey) throws GeneralSecurityException {

		byte[] bytesChecksum = new byte[4];

		System.arraycopy(SHA256Provider.get().sha256(SHA256Provider.get().sha256(bytesAppCodeAndKey)), 0, bytesChecksum, 0, 4);

		return bytesChecksum;
	}

	private static String base58WithAppCodeAndChecksum(byte[] key) throws GeneralSecurityException {

		byte[] bytesAppCodeAndKey = new byte[33];
		bytesAppCodeAndKey[0] = EC25519Constants.XDI_APPCODE_EC25519;
		System.arraycopy(key, 0, bytesAppCodeAndKey, 1, 32);

		byte[] bytesChecksum = checksum(bytesAppCodeAndKey);

		byte[] bytes = new byte[37];
		System.arraycopy(bytesAppCodeAndKey, 0, bytes, 0, 33);
		System.arraycopy(bytesChecksum, 0, bytes, 33, 4);

		return Base58.encode(bytes);
	}
}
