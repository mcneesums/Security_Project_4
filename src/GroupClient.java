 /* Implements the GroupClient Interface */

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
 import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
 
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;

public class GroupClient extends Client implements GroupClientInterface {
	
	protected X509Certificate cert;
	//protected PublicKey publicKey;
	//private Key sessionKey;
	public String FSIP;
	
	public GroupClient(String inputServer, int inputPort, ClientController _cc) {
		super(inputServer, inputPort, _cc);
		publicKey = null;
		cert = null;
		
		// Import the public key
		PEMReader reader = null;
		try {
			reader = new PEMReader(new FileReader("public-cert.pem"));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		Object pemObject = null;
		try {
			pemObject = reader.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (pemObject instanceof X509Certificate) {
		    X509Certificate cert = (X509Certificate)pemObject;
		    try {
				cert.checkValidity(); // to check it's valid in time
				publicKey = cert.getPublicKey();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		}
		if(publicKey == null) {
			System.out.println("Problem setting up the public key.");
		}
		else {
			System.out.println("Imported the public key: " + new String(Hex.encode(publicKey.getEncoded())));
		}
	}
	
	
	public boolean connect() {
		if (!super.connect())
			return false;
		
		// Create a secure random number generator
		SecureRandom rand = new SecureRandom();
		
		// Get random integer nonce
		int nonce = rand.nextInt();
		
		// Generate an AES128 key
		System.out.println("Generating an AES 128 key...");
		
		KeyGenerator AESkeygen = null;
		Key AES128key = null;
		
		try {
			AESkeygen = KeyGenerator.getInstance("AES", "BC");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Initialize with a key size of 128
		AESkeygen.init(128);
		
		// Actual key generation
		AES128key = AESkeygen.generateKey();
		
		// Create the payload ArrayList with the key and the nonce
		ArrayList<Object> payloadList = new ArrayList<Object>();
		payloadList.add(AES128key);
		payloadList.add(nonce);
		sessionKey = AES128key;

		// Initialize the secure session
		int nonceReturn = beginSession(payloadList);
		
		// If the group server returns the nonce - 1, then we know it is actually the group server.
		// We also know to begin using the session key
		if (nonceReturn == (nonce - 1)) {
			System.out.println("Successfully created a secure session!");
			return true;
		}
		else {
			sessionKey = null;
			
			//
			// TODO: Might have to modify this later to have an encrypted disconnect
			secureDisconnect();
			//
			
			return false;
		}
	}


	private int beginSession(ArrayList<Object> list) {
		try
		{
			//Envelope message = null, response = null;
			SecureEnvelope secureMessage = null;
			SecureEnvelope response = null;
			
			// Create the secure message
			secureMessage = new SecureEnvelope("SESSIONINIT");
			
			// Set the payload using the encrypted ArrayList
			secureMessage.setPayload(encryptPayload(listToByteArray(list), false, null));
			
			// Write the envelope to the socket
			output.writeObject(secureMessage);
		
			// Get the response from the server
			response = (SecureEnvelope)input.readObject();
			
			ArrayList<Object> objectList = getDecryptedPayload(response);
			String responsemsg = (String) objectList.get(0);
			
			//Successful response
			if(responsemsg.equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					usercounter = (Integer)objectList.get(1);
					int returnNonce = (Integer)temp.get(0);
					return returnNonce;
				}
			}
			
			return -1;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return -1;
		}
	}

	public Token getToken(String username, String password)
	 {
		try
		{
			Token token = null;
			//Envelope message = null, response = null;
		 	SecureEnvelope message, response = null;
			
			// Make a temporary ArrayList which which be converted to a byte array
			ArrayList<Object> tempList = new ArrayList<Object>();
			
			// Add the username
			tempList.add(username);
			tempList.add(password);
			
			// Make a new SecureEnvelope using the appropriate method
			// Set the message type to GET to return a token
			message = makeSecureEnvelope("GET", tempList);
			
			output.writeObject(message);
		
			//Get the response from the server
			response = (SecureEnvelope)input.readObject();
			
			ArrayList<Object> objectList = getDecryptedPayload(response);
			String responsemsg = (String) objectList.get(0);
			int countertemp = (Integer)objectList.get(1);
			//Successful response
			if(verifyCounter(countertemp) && responsemsg.equals("OK"))
			{	
				if(objectList.size() == 3)
				{
					token = (Token)objectList.get(2);
					return token;
				}
			}
			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	
	public UserToken updateToken(UserToken old, String IP)
	 {
		try
		{
			UserToken token = null;
			//Envelope message = null, response = null;
		 	SecureEnvelope message, response = null;

			// Make a temporary ArrayList which which be converted to a byte array
			ArrayList<Object> tempList = new ArrayList<Object>();

			// Add the username
			tempList.add(old);
			tempList.add(IP);

			// Make a new SecureEnvelope using the appropriate method
			// Set the message type to GET to return a token
			message = makeSecureEnvelope("UTOKEN", tempList);

			output.writeObject(message);

			//Get the response from the server
			response = (SecureEnvelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("UPDATED"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = getDecryptedPayload(response);

				if(temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
					return token;
				}
			}

			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	 }
	 
    public boolean createUser(String username, String password, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(username);
				list.add(password);
				list.add(token);
				secureMessage = makeSecureEnvelope("CUSER", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 	try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(username);
				list.add(token);
				secureMessage = makeSecureEnvelope("DUSER", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(groupname);
				list.add(token);
				secureMessage = makeSecureEnvelope("CGROUP", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(groupname);
				list.add(token);
				secureMessage = makeSecureEnvelope("DGROUP", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(group);
				list.add(token);
				secureMessage = makeSecureEnvelope("LMEMBERS", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return (ArrayList<String>)(getDecryptedPayload(secureResponse).get(2));
				}
				
				return null;
			}
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(username);
				list.add(groupname);
				list.add(token);
				secureMessage = makeSecureEnvelope("AUSERTOGROUP", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean addOwnerToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(username);
				list.add(groupname);
				list.add(token);
				secureMessage = makeSecureEnvelope("AOWNERTOGROUP", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				SecureEnvelope secureMessage = null, secureResponse = null;
				ArrayList<Object> list = new ArrayList<Object>();
				list.add(username);
				list.add(groupname);
				list.add(token);
				secureMessage = makeSecureEnvelope("RUSERFROMGROUP", list);
				output.writeObject(secureMessage);
				
				secureResponse = (SecureEnvelope)input.readObject();
				ArrayList<Object> objectList = getDecryptedPayload(secureResponse);
				String responsemsg = (String)objectList.get(0);
				int countertemp = (Integer)objectList.get(1);
				
				//If server indicates success, return true
				if(verifyCounter(countertemp) && responsemsg.equals("OK"))
				{				
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
}
