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
import javax.crypto.spec.SecretKeySpec;

import Seguridad.CertificadoDigital;
import Seguridad.CifradoAsimetrico;
import Seguridad.CifradoSimetrico;
import Seguridad.ResumenDigital;
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
	private SecretKey llaveSecreta;
	private Socket socket;
	
	public Cliente(){
		ipServidor = "infracomp.virtual.uniandes.edu.co";
		puerto = 443;
		inicializarLlavesCliente();
	}
	
	public void comunicarse(String datos){
		iniciarConexion();
		if(!handshake()){
			System.out.println("Termina en handshake");
		}
		if(!algoritmos()){
			System.out.println("Termina en Algoritmos");
		}
		if(!autenticacionServidor()){
			System.out.println("Termina en Autenticación del Servidor");
		}
		if(!autenticacionCliente()){
			System.out.println("Termina en Autenticación del Cliente");
		}
		if(!llaveSimetrica()){
			System.out.println("Termina en Llave Simetrica");
		}
		if(!enviarInfo(datos)){
			System.out.println("Termina en Enviar Datos");
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
				byte [] llaveSecretaEcriptada = Transformacion.destransformar(partesMensaje[1]);
				byte [] llaveSecretaEnBytes = CifradoAsimetrico.descifrar(llaveSecretaEcriptada, llavesCliente.getPrivate());
				llaveSecreta = new SecretKeySpec(llaveSecretaEnBytes, 0, llaveSecretaEnBytes.length, "AES");
				out.println(INIT + SEPARADOR + Transformacion.transformar(CifradoAsimetrico.cifrarConPublica(llavePublicaServidor, llaveSecretaEnBytes)));
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
	
	public boolean enviarInfo(String datos){
		
		byte[] datosEnBytes = datos.getBytes();
		byte[] datosCifrados = CifradoSimetrico.cifrar(llaveSecreta, datosEnBytes);
		String datosTransformados = Transformacion.transformar(datosCifrados);
		out.println(INFO + SEPARADOR + datosTransformados);
		byte[] hashDatos = ResumenDigital.calcular(datos, llaveSecreta.getEncoded());
		byte[] hashDatosCifrado = CifradoAsimetrico.cifrarConPrivada(llavesCliente.getPrivate(), hashDatos);
		String hashTransformado = Transformacion.transformar(hashDatosCifrado);
		out.println(INFO + SEPARADOR + hashTransformado);
		
		try {
			String mensaje = in.readLine();
			String[] partesMensaje = mensaje.split(SEPARADOR);
			if(partesMensaje[0].equals(INFO)){
				String rtaCifrada = partesMensaje[1];
				byte [] rtaDescifrada = CifradoSimetrico.descifrar(Transformacion.destransformar(rtaCifrada), llaveSecreta);
				String rta = new String(rtaDescifrada);
				System.out.println(rta);
				if (rta.equals(OK)){
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
			e.printStackTrace();
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
		String datos = null;
		
		BufferedReader lector = new BufferedReader( new InputStreamReader(System.in)); 
		
		try {
			System.out.println("Datos: ");
			datos = lector.readLine();
		} catch (IOException e) {
			System.err.println("Datos Exception: " + e.getMessage());
			System.exit(1);
		}
		
		Cliente cliente = new Cliente();
		cliente.comunicarse(datos);
	}

}
