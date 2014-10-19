package Seguridad;

import java.io.*;
import java.security.*;
import javax.crypto.*;

public class ResumenDigital {

	private final static String ALGORTIMO = "DSA";
	private KeyPair keyPair;

	public byte[] calcular() {
		try {
			KeyPairGenerator generator = 
					KeyPairGenerator.getInstance(ALGORTIMO);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
			PrivateKey priv = keyPair.getPrivate();
			PublicKey pub = keyPair.getPublic();
			System.out.println(pub);
			Signature firma = Signature.getInstance(priv.getAlgorithm());firma.initSign(priv);
			FileInputStream arch = new FileInputStream(new File("./archivo.txt"));
			BufferedInputStream bufin = new BufferedInputStream(arch);
			byte [] buffer = new byte[1024];
			int len; 
			//calcula hash
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				firma.update(buffer,0,len);
			}
			bufin.close();
			//firma con la privada
			byte [] signature = firma.sign();
			String s1 = new String(signature);
			System.out.println("Firma: " + s1);
			return signature;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public void verificar(byte[] firma) {
		try {
			PublicKey pub = keyPair.getPublic();
			Signature sig = Signature.getInstance(pub.getAlgorithm());
			sig.initVerify(pub);
			FileInputStream arch = new FileInputStream(new File("./archivo.txt"));
			BufferedInputStream bufin = new BufferedInputStream(arch);
			byte [] buffer = new byte[1024];
			int len; 
			//vuelve a calcular localmente el hash
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				sig.update(buffer,0,len);
			}
			bufin.close();
			//descifra la firma para obtener el hash y hacer la comparación
			boolean verifies = sig.verify(firma);
			System.out.println("Verificacion: " + verifies);
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
		}
	}

}