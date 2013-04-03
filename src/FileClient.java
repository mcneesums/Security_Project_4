/* FileClient provides all the client functionality regarding the file server */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class FileClient extends Client implements FileClientInterface {

	private PublicKey publicKey;
	private Key sessionKey;
	private String fingerprint;
	public String FSIP;
	
	public FileClient(String inputServer, int inputPort, ClientController cc) {
		super(inputServer, inputPort, cc);
		// TODO Auto-generated constructor stub
	}
	
	public boolean connect() {
		if (!super.connect())
			return false;
		
		return getPublicKey();
	}
	
	public String getFingerprint() {
		return fingerprint;
	}


	private int beginSession(ArrayList<Object> list) {
		try
		{
			//Envelope message = null, response = null;
			SecureEnvelope secureMessage = null;
			Envelope response = null;
			
			// Create the secure message
			secureMessage = new SecureEnvelope("SESSIONINIT");
			
			// Set the payload using the encrypted ArrayList
			secureMessage.setPayload(encryptPayload(listToByteArray(list), false, null));
			
			// Write the envelope to the socket
			output.writeObject(secureMessage);
		
			// Get the response from the server
			System.out.println("right before waiting contents");
			response = (Envelope)input.readObject();
			
			//Successful response
			
			if(response.getMessage().equals("OK"))
			{
				System.out.println("Made it in");
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					int returnNonce = (Integer)temp.get(0);
					System.out.println("Nonce: "+returnNonce);
					return returnNonce;
				}
			}
			System.out.println("Failed");
			return -1;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return -1;
		}
	}
	
	private boolean getPublicKey() {
		Envelope message = null;
		try {
			message = (Envelope)input.readObject();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if ((message != null) && message.getMessage().equals("KEYANNOUNCE")) {
			publicKey = (PublicKey)message.getObjContents().get(0);
			if(publicKey == null) {
				System.out.println("Problem getting the public key.");
			}
			else {
				fingerprint = new String(Base64.encode(publicKey.getEncoded()));
				System.out.println("Got the public key: " + fingerprint);
				
			}
			return true;
		}
		else {
			return false;
		}
	}
	
	public boolean setupChannel() {
		
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
		payloadList.add(FSIP);
		
		// Initialize the secure session
		int nonceReturn = beginSession(payloadList);
		
		// If the group server returns the nonce - 1, then we know it is actually the group server.
		// We also know to begin using the session key
		if (nonceReturn == (nonce - 1)) {
			sessionKey = AES128key;
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

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		ArrayList<Object> list = new ArrayList<Object>();
		list.add(remotePath);
		list.add(token);
		SecureEnvelope secureEnv = makeSecureEnvelope("DELETEF", list);
	    
	    try {
			output.writeObject(secureEnv);
			secureEnv = (SecureEnvelope)input.readObject();
		    
			if (secureEnv.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, secureEnv.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    ArrayList<Object> list = new ArrayList<Object>();
						list.add(sourceFile);
						list.add(token);
						SecureEnvelope secureResponse = makeSecureEnvelope("DOWNLOADF", list);
						output.writeObject(secureResponse);
					
						SecureEnvelope secureMessage = (SecureEnvelope)input.readObject();
					    
						while (secureMessage.getMessage().compareTo("CHUNK")==0) {
							ArrayList<Object> tempList = getDecryptedPayload(secureMessage);
							fos.write((byte[])tempList.get(0), 0, (Integer)tempList.get(1));
							System.out.printf(".");
							secureResponse = new SecureEnvelope("DOWNLOADF"); //Success
							output.writeObject(secureResponse);
							secureMessage = (SecureEnvelope)input.readObject();									
						}										
						fos.close();
						
					    if(secureMessage.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								secureResponse = new SecureEnvelope("OK"); //Success
								output.writeObject(secureResponse);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, secureMessage.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		try {
			 
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(token);
			SecureEnvelope secureMessage = makeSecureEnvelope("LFILES", list);
			
			Envelope e = null;
			 
			output.writeObject(secureMessage); 
			 
			SecureEnvelope secureEnv = (SecureEnvelope)input.readObject();
			 
			//If server indicates success, return the member list
			if(secureEnv.getMessage().equals("OK")) {
				ArrayList<Object> tempList = getDecryptedPayload(secureEnv);
				return (List<String>)tempList.get(0); //This cast creates compiler warnings. Sorry.
			}
				
			return null;
			 
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			destFile = "/" + destFile;
		}
		
		try {
			ArrayList<Object> list = new ArrayList<Object>();
			list.add(destFile);
			list.add(group);
			list.add(token);
			SecureEnvelope secureMessage = makeSecureEnvelope("UPLOADF", list);
			SecureEnvelope secureEnv;
			
			 output.writeObject(secureMessage);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 secureEnv = (SecureEnvelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(secureEnv.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", secureEnv.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (secureEnv.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", secureEnv.getMessage());
				 		return false;
				 	}
				 	
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					ArrayList<Object> tempList = new ArrayList<Object>();
					tempList.add(buf);
					tempList.add(new Integer(n));
					secureMessage = makeSecureEnvelope("CHUNK", tempList);
					
					
					output.writeObject(secureMessage);
					
					secureEnv = (SecureEnvelope)input.readObject();
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(secureEnv.getMessage().compareTo("READY")==0)
			 { 
				
				secureMessage = new SecureEnvelope("EOF");
				output.writeObject(secureMessage);
				
				secureEnv = (SecureEnvelope)input.readObject();
				if(secureEnv.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", secureEnv.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", secureEnv.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	
	
	/* Crypto Related Methods
	 * 
	 * These methods will abstract the whole secure session process.
	 * 
	 */
	 
	private SecureEnvelope makeSecureEnvelope(String msg, ArrayList<Object> list) {
		// Make a new envelope
	SecureEnvelope envelope = new SecureEnvelope(msg);
	
	// Create new ivSpec
	IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
	
	// Set the ivSpec in the envelope
	envelope.setIV(ivSpec.getIV());
	
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
	
	protected byte[] listToByteArray(ArrayList<Object> list) {
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

}

