package src;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;
import java.util.Properties;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidKeyException;

public class secureCore {
	/*private static final String HMAC_SHA512 = "HmacSHA512";
	private static final String HMAC_SHA384 = "HmacSHA384";
	private static final String HMAC_SHA256 = "HmacSHA256";
	private static final String HMAC_SHA1 = "HmacSHA1";
	private static final String HMAC_MD5 = "HmacMD5";
	*/
	
	/*public static String importPass() {
		Properties prop = new Properties();
		try {
			FileInputStream ip = new FileInputStream(importConfig().get(0));
			try {
				prop.load(ip);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println(e.getMessage());
			}
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		}
		return prop.getProperty("pass");
	}

	
	
	private static String toHexString(byte[] bytes) {
		@SuppressWarnings("resource")
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}
	
	public static String calculateHMAC(String data, String key, int algo)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

		// POR DEFECTO PONEMOS HMAC SHA 512
		SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA512);
		Mac mac = Mac.getInstance(HMAC_SHA512);
		if (algo == 0) {
			secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_MD5);
			mac = Mac.getInstance(HMAC_MD5);
		} else if (algo == 1) {
			secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
			mac = Mac.getInstance(HMAC_SHA1);
		} else if (algo == 2) {
			secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA256);
			mac = Mac.getInstance(HMAC_SHA256);
		} else if (algo == 3) {
			secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA384);
			mac = Mac.getInstance(HMAC_SHA384);
		} else if (algo == 4) {
			secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA512);
			mac = Mac.getInstance(HMAC_SHA512);
		}
		try {
			mac.init(secretKeySpec);
		} catch (java.security.InvalidKeyException e) {
			System.out.println(e.getMessage());
		}
		return toHexString(mac.doFinal(data.getBytes()));
	}
	*/

	public static List<Integer> readStats() {
		Properties prop = new Properties();
		try {
			FileInputStream ip = new FileInputStream(importConfig().get(1));
			try {
				prop.load(ip);
			} catch (IOException e) {
				System.out.println(e.getMessage());
			}
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		}
		return Arrays.asList(Integer.parseInt(prop.getProperty("successfull")),
				Integer.parseInt(prop.getProperty("unsuccessfull")));

	}
	public static List<String> importConfig() {
		Properties prop = new Properties();
		try {
			FileInputStream ip = new FileInputStream("src//config.properties");
			try {
				prop.load(ip);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println(e.getMessage());
			}
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		}
		return Arrays.asList(prop.getProperty("dirPass"), prop.getProperty("dirStats"));
	}
	public static void writeStats(String key, String value) throws IOException {
		Properties prop = new Properties();
		try {
			FileInputStream ip = new FileInputStream(importConfig().get(1));
			prop.load(ip);
			prop.setProperty(key, value);
			prop.store(new FileOutputStream(importConfig().get(1)),
					null);
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		}
	}



}
