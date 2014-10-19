package Seguridad;

import java.io.*;
import java.security.*;
import javax.crypto.*;

public class CifradoAsimetrico {
	
	private final static String ALGORITMO="RSA";
//	private KeyPair keyPair;

	public static byte[] cifrarConPublica(PublicKey llavePublica, byte[] text) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			//byte [] clearText = text.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
			byte [] cipheredText = cipher.doFinal(text);
//			System.out.println("clave cifrada: " + cipheredText);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Asimétrico (con publica) Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static byte[] cifrarConPrivada(PrivateKey llavePrivada, byte[] text) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			//byte [] clearText = text.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, llavePrivada);
			byte [] cipheredText = cipher.doFinal(text);
//			System.out.println("clave cifrada: " + cipheredText);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Asimétrico (con privada) Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public static byte[] descifrar(byte[] cipheredText, PrivateKey llavePrivada) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
			byte [] res = cipher.doFinal(cipheredText);
//			String res = new String(clearText);
//			System.out.println("clave del servidor: " + res);
			return res;
		} 
		catch (Exception e) {
			System.err.println("Descifrado Asimétrico Excepcion: " + e.getMessage());
		}
		return null;
	}

}