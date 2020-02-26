import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Protocol1Attack {

	static int portNo = 11337;

	public static void main(String[] args) {
		try {
			InetAddress host = InetAddress.getLocalHost();
			Socket socket = new Socket(host, portNo);
			Thread instance = new Thread(new Protocol1AttackInstance(socket));
			instance.start();
		} catch (Exception e) {
			System.out.println("Client error " + e);
		}
	}
}

class Protocol1AttackInstance implements Runnable {

	Socket myConnection;
	boolean debug = true;
	static Cipher decAEScipher;
	static Cipher encAEScipher;
	String hexKey;

	public Protocol1AttackInstance(Socket myConnection) {
		this.myConnection = myConnection;

	}

	public void run() {
		OutputStream outStream;
		InputStream inStream;

		try {
			outStream = myConnection.getOutputStream();
			inStream = myConnection.getInputStream();

			// Protocol Step 1
			// Send "Connect Protocol 1"
			byte[] message1 = "Connect Protocol 1".getBytes();
			outStream.write(message1);
			if (debug)
				System.out.println("Sent message");

			// Protocol Step 2
			// receive Nonce
			byte[] serverNonce = new byte[32];
			inStream.read(serverNonce);
			if (debug)
				System.out.println("recieved nonce" + byteArrayToHexString(serverNonce));

			// Protocol Step 3
			// send Nonce
			outStream.write(serverNonce);
			if (debug)
				System.out.println("sent nonce" + byteArrayToHexString(serverNonce));

			// get Encryption from Server
			byte[] sesskeyBytes = new byte[16];
			SecretKeySpec secretKeySpec = new SecretKeySpec(sesskeyBytes, "AES");

			Cipher decAEScipherSession = Cipher.getInstance("AES");
			decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);

			Cipher encAEScipherSession = Cipher.getInstance("AES");
			encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			if (debug)
				System.out.println("Session key :" + byteArrayToHexString(sesskeyBytes));
			// step 4
			byte[] sessionKey = new byte[48];
			inStream.read(sessionKey);
			// step 5
			outStream.write(sessionKey);

			byte[] message = new byte[inStream.available()];
			// step 6
			inStream.read(message);

			byte[] decryptedMessage = decAEScipherSession.doFinal(message);

		} catch (IOException e) {

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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

