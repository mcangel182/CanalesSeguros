package Cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import Seguridad.CertificadoDigital;
import Seguridad.CifradoAsimetrico;
import Seguridad.Transformacion;

public class Cliente {

	public final static String SEPARADOR = ":";
	public final static String HOLA = "HOLA";
	public final static String ACK = "ACK";
	public final static String ALGORITMOS = "ALGORITMOS";
	public final static String ALGS = "AES";
	public final static String ALGA = "RSA";
	public final static String ALGH = "HMACMD5";
	public final static String STATUS = "STATUS";
	public final static String OK = "OK";
	public final static String ERROR = "ERROR";
	public final static String CERTSRV = "CERTSRV";
	public final static String CERTCLNT = "CERCLNT";
	public final static String INIT = "INIT";
	public final static String INFO = "INFO";
	public final static String SEPARADOR_LOGIN = ",";
	
	private String ipServidor;
	private int puerto;
	private BufferedReader in;
	private InputStream inputStream;
	private PrintWriter out;
	private OutputStream outputStream;
	private byte[] certificadoServidor;
	private byte[] certificadoCliente;
	private PublicKey llavePublicaServidor;
	private KeyPair llavesCliente;
	private byte[] llaveSecreta;
	private Socket socket;
	
	public Cliente(){
		ipServidor = "infracomp.virtual.uniandes.edu.co";
		puerto = 443;
		inicializarLlavesCliente();
	}
	
	public void comunicarse(String usuario, String clave){
		iniciarConexion();
		System.out.println("1");
		if(!handshake()){
			System.out.println("Termina en handshake");
		}
		System.out.println("2");
		if(!algoritmos()){
			System.out.println("Termina en Algoritmos");
		}
		System.out.println("3");
		if(!autenticacionServidor()){
			System.out.println("Termina en Autenticación del Servidor");
		}
		System.out.println("4");
		if(!autenticacionCliente()){
			System.out.println("Termina en Autenticación del Cliente");
		}
		System.out.println("5");
		if(!llaveSimetrica()){
			System.out.println("Termina en Llave Simetrica");
		}
	}
	
	public void iniciarConexion(){
		try {
			socket = new Socket(ipServidor, puerto);
			inputStream = socket.getInputStream();
			in = new BufferedReader(new InputStreamReader(inputStream));
			outputStream = socket.getOutputStream();
			out = new PrintWriter(outputStream,true);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean handshake(){
		try {
			out.println(HOLA);
			String respuesta = in.readLine();
			if(respuesta.equals(ACK)){
				return true;
			}
		} catch (Exception e) {
			System.err.println("Handshake Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	public boolean algoritmos(){
		try {
			out.println(ALGORITMOS + SEPARADOR + ALGS + SEPARADOR + ALGA + SEPARADOR + ALGH);
			String respuesta = in.readLine();
			if(respuesta.equals(STATUS + SEPARADOR + OK)){
				return true;
			}
		} catch (Exception e) {
			System.err.println("Algoritmos Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	public boolean autenticacionServidor(){
		String cert;
		try {
			cert = in.readLine();
			if (cert.equals(CERTSRV)){
				certificadoServidor = new byte[1024];
				inputStream.read(certificadoServidor); 
				llavePublicaServidor = CertificadoDigital.darLlavePublica(certificadoServidor);
				System.out.println(llavePublicaServidor);
				return true;
			}
		} catch (IOException e) {
			System.err.println("Autenticación Servidor Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	public boolean autenticacionCliente(){
		try {
			out.println(CERTCLNT);
			X509Certificate certificado = CertificadoDigital.generarCertificado(llavesCliente);
			byte[] cert = certificado.getEncoded();
			outputStream.write(cert);
			outputStream.flush();
			return true;
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean llaveSimetrica(){
		try {
			String mensaje = in.readLine();
			String[] partesMensaje = mensaje.split(SEPARADOR);
			if(partesMensaje[0].equals(INIT)){
				System.out.println("entra");
				byte [] llaveSecretaEcriptada = Transformacion.destransformar(partesMensaje[1]);
				llaveSecreta = CifradoAsimetrico.descifrar(llaveSecretaEcriptada, llavesCliente.getPrivate());
				System.out.println(llaveSecreta);
				out.println(INIT + SEPARADOR + Transformacion.transformar(CifradoAsimetrico.cifrar(llavePublicaServidor, llaveSecreta)));
				String respuesta = in.readLine();
				System.out.println(respuesta);
				if (respuesta.equals(STATUS + SEPARADOR + OK)){
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	private void inicializarLlavesCliente(){
		try {
			KeyPairGenerator generator;
			generator = KeyPairGenerator.getInstance(ALGA);
			generator.initialize(1024);
			llavesCliente = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String usuario = null;
		String clave = null;
		
		BufferedReader lector = new BufferedReader( new InputStreamReader(System.in)); 
		
		try {
			System.out.println("Datos: ");
			usuario = lector.readLine();
		} catch (IOException e) {
			System.err.println("Datos Exception: " + e.getMessage());
			System.exit(1);
		}
		
		Cliente cliente = new Cliente();
		cliente.comunicarse(usuario, clave);
	}

}