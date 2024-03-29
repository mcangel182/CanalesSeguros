package Seguridad;

import java.io.*;
import javax.crypto.*;

/**
 * La clase CifradoSimetrico.
 */
public class CifradoSimetrico {

	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	/** Constante que indica qué el algoritmo se usa para el cifrado. */
	private final static String ALGORITMO="AES";
	
	/** Constante que indica qué el padding se usa para el cifrado. */
	private final static String PADDING="AES/ECB/PKCS5Padding";

	// -----------------------------------------------------------------
	// Métodos
	// -----------------------------------------------------------------
	
	/**
	 * Método que se encarga de cifrar una entrada con una llave secreta.
	 * Retorna la entrada cifrada.
	 * @param llaveSecreta Llave secreta con la que se cifrará.
	 * @param text Entrada a cifrar. 
	 * @return Arreglo de bytes con la entrada cifrada. 
	 */
	public static byte[] cifrar(SecretKey llaveSecreta, byte[] text) {
		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.ENCRYPT_MODE, llaveSecreta);
			cipheredText = cipher.doFinal(text);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Cifrado Simetrico Excepcion: " + e.getMessage());
			return null;
		}
	}

	/**
	 * Método que se encarga de descifrar una entrada con una llave secreta.
	 * Retorna la entrada descifrada.
	 * @param llaveSecreta Llave secreta con la que se cifrará.
	 * @param cipheredText Entrada a descifrar.
	 * @return the byte[]
	 */
	public static byte[] descifrar(SecretKey llaveSecreta, byte [] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, llaveSecreta);
			byte[] res = cipher.doFinal(cipheredText);
			return res;
		}
		catch (Exception e) {
			System.out.println("Descifrado Simetrico Excepcion: " + e.getMessage());
		}
		return null;
	}

}
