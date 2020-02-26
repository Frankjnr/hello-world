public class Protocol1Client {
	
	static int portNo = 11337;

	public static void main(String[] args) {
		try {
			InetAddress host = InetAddress.getLocalHost();
			Socket socket = new Socket(host,portNo);
			Thread instance = new Thread(new ProtocolInstance(socket));
			instance.start();
		} catch (Exception e) {
			System.out.println("Client error " + e)
		}
	}
}

private static class ProtocolInstance implements Runnable {

	Socket myConnection;
	boolean debug = true;
	static Cipher decAEScipher;
	static Cipher encAEScipher;
	String hexKey;

	public ProtocolInstance(Socket myConnection) {
		this.myConnection = myConnection;
	

	}

	public void run() {
		OutputStream outStream;
		InputStream inStream;

		try {
			outSteam = myConnection.getOutputStream();
			inStream = myConnection.getInputSteam();

			//Protocol Step 1
			//Send "Connect Protocol 1"
			byte[] message1 = "Connect Protocol 1".getBytes();
			outStream.write(message1);
			if (debug) System.out.println("Sent message");

		
			//Protocol Step 2
			//receive Nonce
			byte[] serverNonce = new byte[32];
			inStream.read(serverNonce);
			if (debug) System.out.println("recieved nonce" + byteArrayToHexString(serverNonce));

			//Protocol Step 3
			//send Nonce
			outStream.write(serverNonce);
			if (debug) System.out.println("sent nonce" + byteArrayToHexString(serverNonce));
			
			//get Encryption from Server
			byte[] sesskeyBytes = new byte[16];
			SecretKeySpec secretKeySpec = new SecretKeySpec(sessKeyBytes, "AES");
 
			Cipher decAEScipherSession = Cipher.getInstance("AES");
			decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);

			Cipher encAEScipherSession = Cipher.getInstance("AES");
			encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			
 			if (debug) System.out.println("Session key :" + byteArrayToHexString(keyBytes));
				//step 4
				byte[] sessionKey = new byte[48];
				inStream.read(sessionKey);
				//step 5
				outStream.write(sessionKey);

				byte[] message = new byte[inStream.available()];
				//step 6
				instream.read(message);

				byte[] decryptedMessage = decAEScipherSession.doFinal(message);

		} catch (IOException e) {
			
		} catch (InvalidKeyEncryption) {
		
		} catch () {

		} catch () {

		} catch () {

		} catch () {

		}
	}

	private static String byteArrayToHexString(byte[] data) { 
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) { 
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do { 
			if ((0 <= halfbyte) && (halfbyte <= 9)) 
				buf.append((char) ('0' + halfbyte));
			else 
				buf.append((char) ('a' + (halfbyte - 10)));
			halfbyte = data[i] & 0x0F;
			} while(two_halfs++ < 1);
		} 


		return buf.toString();
	} 

	private static byte[] xorBytes (byte[] one, byte[] two) {
	if (one.length!=two.length) {
	    return null;
	} else {
	    byte[] result = new byte[one.length];
	    for(int i=0;i<one.length;i++) {
		result[i] = (byte) (one[i]^two[i]);
	    }
	    return result;
	}
    }
	

}



		}

		
	}
}
