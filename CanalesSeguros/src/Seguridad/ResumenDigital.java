package Seguridad;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ResumenDigital {

	private final static String ALGORITMO = "HMACMD5";
	private KeyPair keyPair;

	public static byte[] calcular(String mensaje, byte[] llave) { 
		try { 
			byte[] text = mensaje.getBytes(); 
			Mac mac = Mac.getInstance(ALGORITMO);
			SecretKeySpec keySpec = new SecretKeySpec(llave, ALGORITMO);
			mac.init(keySpec);
			mac.update(text);
			return mac.doFinal(); 
		} 
		catch (Exception e) { 
			System.out.println("Excepcion: " + e.getMessage()); 
			return null; 
		} 
	} 
}
