package Seguridad;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.*;

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

	public static X509Certificate generarCertificado(KeyPair keyPair){
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			Date startDate = new Date(System.currentTimeMillis());              // time from which certificate is valid
			Date expiryDate = new Date(System.currentTimeMillis()+365*24*60*60*1000);             // time after which certificate is not valid
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());     // serial number for certificate
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=Test CA Certificate");
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA1withRSA");
			X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
			return cert;
		} catch (CertificateEncodingException | InvalidKeyException
				| IllegalStateException | NoSuchProviderException
				| NoSuchAlgorithmException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}