package xdi2.core.security.ec25519.crypto;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.ServiceLoader;

public abstract class SHA256Provider {

	private static SHA256Provider instance;

	public static SHA256Provider get() {

		SHA256Provider result = instance;

		if (result == null) {

			synchronized(SHA256Provider.class) {

				result = instance;

				if (result == null) {

					try {

						Enumeration<URL> e = Thread.currentThread().getContextClassLoader().getResources("META-INF/services/" + SHA256Provider.class.getName());
						if (e.hasMoreElements()) System.out.println("===> " + e.nextElement());
						else System.out.println("===> :(");
					} catch (IOException ex) {
						
						throw new RuntimeException(ex.getMessage(), ex);
					}

					ServiceLoader<SHA256Provider> serviceLoader = ServiceLoader.load(SHA256Provider.class);
					Iterator<SHA256Provider> iterator = serviceLoader.iterator();
					if (! iterator.hasNext()) throw new RuntimeException("No " + SHA256Provider.class.getName() + " registered");

					instance = result = iterator.next();
				}
			}
		}

		return result;
	}

	public static void set(SHA256Provider instance) {
		
		SHA256Provider.instance = instance;
	}
	
	public abstract byte[] sha256(byte[] bytes) throws GeneralSecurityException;
}
