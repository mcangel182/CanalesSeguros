package Seguridad;

import java.io.*;
import java.security.*;
import java.security.cert.*;

public class CertificadoDigital {

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
