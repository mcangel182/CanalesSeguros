package Seguridad;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.x509.*;

/**
 * La clase CertificadoDigital.
 */
public class CertificadoDigital {
	
	// -----------------------------------------------------------------
	// Métodos
	// -----------------------------------------------------------------
	
	/**
	 * Método que genera un certificado digital.
	 * Retorna el certificador digital generado. 
	 * @param keyPair Par de llaves para generar el ecrtificado. 
	 * @return El certificado x509 generado. 
	 */
	public static X509Certificate generarCertificado(KeyPair keyPair){
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			Date startDate = new Date(System.currentTimeMillis());
			Date expiryDate = new Date(System.currentTimeMillis()+365*24*60*60*1000);
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=Test CA Certificate");
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA1withRSA");
			X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
			return cert;
		} catch (Exception e) {
			System.err.println("Generar Certificado Exception: " + e.getMessage());
		}
		return null;
	}
	
	/**
	 * Método que retorna la llave publica de un certificado digital.
	 * Retorna la llave pública que viene en el certficado
	 * @param certEnBytes Los bytes del certificado digital.
	 * @return La llave pública.
	 */
	public static PublicKey darLlavePublica(byte[] certEnBytes){	
		try {
			InputStream inStream = new ByteArrayInputStream(certEnBytes);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificado = (X509Certificate) certFactory.generateCertificate(inStream);
			inStream.close();
			return certificado.getPublicKey();
		} catch (Exception e) {
			System.err.println("Llave Publica Exception: " + e.getMessage());
		}  
		return null;
	}
}
