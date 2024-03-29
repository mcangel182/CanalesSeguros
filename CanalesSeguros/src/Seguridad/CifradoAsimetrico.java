package Seguridad;

import java.io.*;
import java.security.*;
import javax.crypto.*;

/**
 * La clase CifradoAsimetrico.
 */
public class CifradoAsimetrico {
	
	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	/** Constante que indica qué el algoritmo se usa para el cifrado. */
	private final static String ALGORITMO="RSA";

	// -----------------------------------------------------------------
	// Métodos
	// -----------------------------------------------------------------
	
	/**
	 * Método que cifra un arreglo de bytes con una llave pública. 
	 * Retorna el arreglo de bytes con la entrada cifrada.
	 * @param llavePublica La llave pública con la que se encriptará.
	 * @param text Entrada a encriptar.
	 * @return El arreglo de bytes con la entrada cifrada.
	 */
	public static byte[] cifrarConPublica(PublicKey llavePublica, byte[] text) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
			byte [] cipheredText = cipher.doFinal(text);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Asimétrico (con publica) Excepcion: " + e.getMessage());
			return null;
		}
	}

	/**
	 * Método que cifra un arreglo de bytes con una llave privada. 
	 * Retorna el arreglo de bytes con la entrada cifrada.
	 * @param llavePrivada La llave privada con la que se encriptará.
	 * @param text Entrada a encriptar.
	 * @return El arreglo de bytes con la entrada cifrada.
	 */
	public static byte[] cifrarConPrivada(PrivateKey llavePrivada, byte[] text) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, llavePrivada);
			byte [] cipheredText = cipher.doFinal(text);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Asimétrico (con privada) Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	/**
	 * Método que permite descifrar una entrada usando una llave privada. 
	 * Retorna la entrada descifrada. 
	 * @param llavePrivada La llave privada con la que se desencripta.
	 * @param cipheredText Entrada a descifrar.
	 * @return El arreglo de bytes con la entrada descifrada.
	 */
	public static byte[] descifrar(PrivateKey llavePrivada, byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
			byte [] res = cipher.doFinal(cipheredText);
			return res;
		} 
		catch (Exception e) {
			System.err.println("Descifrado Asimétrico Excepcion: " + e.getMessage());
		}
		return null;
	}

}
