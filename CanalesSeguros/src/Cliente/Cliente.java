package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

public class Cliente {

	public final static String SEPARADOR = ":";
	public final static String HOLA = "HOLA";
	public final static String STATUS = "STATUS";
	public final static String ACK = "ACK";
	public final static String ALGORITMOS = "ALGORITMOS";
	public final static String ALGS = "AES";
	public final static String ALGA = "RSA";
	public final static String ALGH = "HMACMD5";
	public final static String CERTSRV = "CERTSRV";
	public final static String AUTHENTICATION = "AUT";
	public final static String SEPARADOR_LOGIN = ",";
	public final static String TUTELA = "STATTUTELA";
	public final static String INFO = "INFO";
	public final static String RESULTADO = "RESULTADO";
	public final static String OK = "OK";
	public final static String ERROR = "ERROR";
	public final static String FIN = "FIN";
	
	private String ipServidor;
	private int puerto;
	private BufferedReader in;
	private PrintWriter out;
	
	public Cliente(){
		ipServidor = "infracomp.virtual.uniandes.edu.co";
		puerto = 443;
	}
	
	public void comunicarse(String usuario, String clave){
		iniciarConexion();
		
		if(!handshake()){
			System.out.println("no respondio handshake");
		}
	}
	
	public void iniciarConexion(){
		try {
			Socket sockect = new Socket(ipServidor, puerto);
			in = new BufferedReader(new InputStreamReader(sockect.getInputStream()));
			out = new PrintWriter(sockect.getOutputStream(),true);
			
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
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String usuario = null;
		String clave = null;
		
		BufferedReader lector = new BufferedReader( new InputStreamReader(System.in)); 
		
		try {
			System.out.println("Login: ");
			usuario = lector.readLine();
			System.out.println("Clave: ");
			clave = lector.readLine();

		} catch (IOException e) {
			System.err.println("Datos Exception: " + e.getMessage());
			System.exit(1);
		}
		
		Cliente cliente = new Cliente();
		cliente.comunicarse(usuario, clave);
	}

}
