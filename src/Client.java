import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected String myServer;
	protected int myPort;
	protected ClientController controller;
	protected Key sessionKey;
	protected Key hashKey;
	protected PublicKey publicKey;
	protected int usercounter;

	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");

		try{
		    // Connect to the specified server
		    sock = new Socket(server, port);
		    
		    // Set up I/O streams with the server
		    output = new ObjectOutputStream(sock.getOutputStream());
		    input = new ObjectInputStream(sock.getInputStream());
		    return true;
		}
		catch(Exception e){
		    System.err.println("Error: " + e.getMessage());
		    e.printStackTrace(System.err);
		    return false;
		}
	}
	
	public boolean connect() {
		return connect(myServer, myPort);
	}
	
	public Client (String inputServer, int inputPort, ClientController _controller) {
		myServer = inputServer;
		myPort = inputPort;
		controller = _controller;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
	public void secureDisconnect() {
		if (isConnected()) {
			try
			{
				SecureEnvelope secureMessage = new SecureEnvelope("DISCONNECT");
				output.writeObject(secureMessage);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
	
	/* Crypto Related Methods
	 * 
	 * These methods will abstract the whole secure session process.
	 * 
	 */
	protected  SecureEnvelope makeSecureEnvelope(String msg)
	{
		ArrayList<Object> list = new ArrayList<Object>();
		return makeSecureEnvelope(msg, list);
	}
	 
	protected SecureEnvelope makeSecureEnvelope(String msg, ArrayList<Object> list) {
		// Make a new envelope
	SecureEnvelope envelope;

	if(msg.equals("SESSIONINIT"))
	{
		envelope = new SecureEnvelope(msg);
	} 
	else
	{
		envelope = new SecureEnvelope("");
	}
	
	// Create new ivSpec
	IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
	
	// Set the ivSpec in the envelope
	envelope.setIV(ivSpec.getIV());
	System.out.print(envelope.getIV());
	
	usercounter++;
	System.out.println("Sent over C-G: " + usercounter);

	list.add(0, usercounter);
	list.add(0, msg);
	
	// Set the payload using the encrypted ArrayList
		envelope.setPayload(encryptPayload(listToByteArray(list), true, ivSpec));
		
		return envelope;
		
	}
	
	private byte[] encryptPayload(byte[] plainText, boolean useSessionKey, IvParameterSpec ivSpec) {
		byte[] cipherText = null;
		Cipher inCipher;
		
		if (useSessionKey) {
			// TODO
		try {
			inCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			inCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
			cipherText = inCipher.doFinal(plainText);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	else { // Use public key RSA
		try {
			inCipher = Cipher.getInstance("RSA", "BC");
			inCipher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
			System.out.println("plainText length: " + plainText.length);
			cipherText = inCipher.doFinal(plainText);
		} catch (Exception e) {
			// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return cipherText;
	}
	
	private ArrayList<Object> getDecryptedPayload(SecureEnvelope envelope) {
		// Using this wrapper method in case the envelope changes at all :)
		System.out.println("check evelope" + envelope.getIV());
		return byteArrayToList(decryptPayload(envelope.getPayload(), new IvParameterSpec(envelope.getIV())));
	}
	
	private byte[] decryptPayload(byte[] cipherText, IvParameterSpec ivSpec) {
		Cipher outCipher = null;
		byte[] plainText = null;
		
		try {
			outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		outCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		plainText = outCipher.doFinal(cipherText);
	} catch (Exception e) {
		// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return plainText;
	}
	
	private byte[] listToByteArray(ArrayList<Object> list) {
		byte[] returnBytes = null;
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(list);
		  returnBytes = bos.toByteArray();
		  out.close();
		  bos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return returnBytes;
	}
	
	private ArrayList<Object> byteArrayToList(byte[] byteArray) {
		ArrayList<Object> list = null;
		
		ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
		ObjectInput in = null;
		try {
		  in = new ObjectInputStream(bis);
		  Object object = in.readObject();
		  list = (ArrayList<Object>)object;
		  bis.close();
		  in.close();
		  
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return list;
	}
	
	protected boolean verifyCounter(int numcount)
	{
		boolean verified = false;
		usercounter++;
		System.out.println("numcount: " + numcount + " usercount: " + usercounter);
		
		if(numcount == usercounter)
		{	
			verified = true;	
		}
		else
		{
			System.out.println("Counter not correct. Not a safe message. Closing network!");
			System.exit(0);
		}

		return verified;
	}
	
	protected byte[] createHMAC(byte[] message)
	{
		if(message == null)
		{
			return null;
		}
		
		try
		{
			Mac mac = Mac.getInstance(hashKey.getAlgorithm());
			mac.init(hashKey);
			byte[] hmacValue = mac.doFinal(message);
			return hmacValue;
		 } 
		catch (Exception e)
		{
			e.printStackTrace();
		}
			    
		return null;  
	}
	
	protected boolean vierfyHMAC(byte[] hashvalue, byte[] message, Key key)
	{
		try 
		{
			Mac mac = Mac.getInstance(key.getAlgorithm());
			mac.init(key);
			byte[] hashVal = mac.doFinal(message);
			return Arrays.equals(hashVal, hashvalue);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		return false;
	}
	
	
}
