package Seguridad;

import java.io.*;
import javax.crypto.*;

public class CifradoSimetrico {

//	private SecretKey desKey;
	private final static String ALGORITMO="AES";
	private final static String PADDING="AES/ECB/PKCS5Padding";

	public static byte[] cifrar(SecretKey desKey, byte[] text) {
		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(text);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Simetrico Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrar(byte [] cipheredText, SecretKey desKey) {
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] res = cipher.doFinal(cipheredText);
			return res;
		}
		catch (Exception e) {
			System.out.println("Descifrado Simetrico Excepcion: " + e.getMessage());
		}
		return null;
	}

}
