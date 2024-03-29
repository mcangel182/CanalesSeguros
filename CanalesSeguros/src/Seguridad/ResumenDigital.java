package Seguridad;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * La clase ResumenDigital.
 */
public class ResumenDigital {

	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------
	
	/** Constante que indica qué el algoritmo se usa para calcular el HMAC. */
	private final static String ALGORITMO = "HMACMD5";

	// -----------------------------------------------------------------
	// Métodos
	// -----------------------------------------------------------------
	
	/**
	 * Método que calcula el código criptográfico de una entrada.
	 *
	 * @param mensaje Mensaje del cual se quiere calcular el código criptográfico. 
	 * @param llave Llave con la que se construye el código.
	 * @return El arreglo de bytes correspondiente al código criptográfico. 
	 */
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
			System.out.println("Resumen Digital Excepcion: " + e.getMessage()); 
			return null; 
		} 
	} 
}
