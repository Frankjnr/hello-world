
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//1. C -> S: g^x
//2. S -> C: g^y,  
//3. C -> S: {  Nc  }_key(g^xy)
//4. S -> C: {  {Nc+1}_Kcs, Ns  }_key(g^xy)
//5. C -> S: {  {Ns+1}_Kcs  }_key(g^xy)
//6. S -> C: {secret}_key(g^xy)
public class Protocol2Attack {

    static int portNo = 11338;

    // Values of p & g for Diffie-Hellman found using generateDHprams()
    static BigInteger g = new BigInteger(
            "129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
    static BigInteger p = new BigInteger(
            "165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");

    public static void main(String[] args) {

        try {
            Socket socket = new Socket("127.0.0.1", portNo);
            ProtocolClientInstance clientInstance = new ProtocolClientInstance(socket);
            clientInstance.run();

        } catch (IOException e) {
            System.out.println("error in client " + e);
        }
    }

    public static class ProtocolClientInstance {
        Socket clientSocket;
        Cipher decAESsessionCipher;
        Cipher encAESsessionCipher;
        boolean debug = true;

        public ProtocolClientInstance(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        public void run() {
            DataOutputStream outStream;
            DataInputStream inStream;

        
            try {
                outStream = new DataOutputStream(clientSocket.getOutputStream());
                inStream = new DataInputStream(clientSocket.getInputStream());

                // Use crypto API to calculate y & g^y
                DHParameterSpec dhSpec = new DHParameterSpec(p,g);
                KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
                diffieHellmanGen.initialize(dhSpec);
                KeyPair serverPair = diffieHellmanGen.generateKeyPair();
                PrivateKey x = serverPair.getPrivate();
                PublicKey gToTheX = serverPair.getPublic();

                //Protocol message 1
                outStream.writeInt(gToTheX.getEncoded().length);
                outStream.write(gToTheX.getEncoded());
                
                //Protocol message2
                int publicKeyLen = inStream.readInt();
                byte[] message1 = new byte[publicKeyLen];
                inStream.read(message1);
                KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
                PublicKey gToTheY= keyfactoryDH.generatePublic(x509Spec);

                //Calculate session key
                // This method sets decAESsessionCipher & encAESsessionCipher
                calculateSessionKey(x, gToTheY);
                
                //Step 3
                //Send encrypted nonce to server
                SecureRandom secureRandom = new SecureRandom();
                int clientNonce = secureRandom.nextInt();
                byte[] clientNonceInBytes = BigInteger.valueOf(clientNonce).toByteArray();
                byte[]  encryptedClientNonce= encAESsessionCipher.doFinal(clientNonceInBytes);
                outStream.write(encryptedClientNonce);
                
                if (debug) System.out.println("(1) sent nonce => server: "+clientNonce);
                
                //Step 4
                //received a nonce from the server
                byte[] message4ct = new byte[32];
                inStream.read(message4ct);
                byte[] decryptedServerNonce= decAESsessionCipher.doFinal(message4ct);
                if (debug) System.out.println("(2) server sent me this "+decryptedServerNonce);
                byte[] serverNonce = new byte[4];
                System.arraycopy(decryptedServerNonce, 16, serverNonce, 0, 4);
                if (debug) System.out.println("(3) i sent this to client 2"+serverNonce);

                //Step 5
                //send the server the encrypted nonce 
                Socket Socket = new Socket("127.0.0.1",portNo);
                ProtocolClientInstance1 attacker = new ProtocolClientInstance1(Socket,serverNonce); 
                attacker.run();

                //Step 6
                //send an encrypted nonce from 2nd client to Server
                byte [] encryptedServer  = attacker.getClientEncKey();
				byte[]  encryptedServerNonce= encAESsessionCipher.doFinal(encryptedServer);
                outStream.write(encryptedServerNonce);
                if (debug) System.out.println("8 i recieved this from client 2"+encryptedServer);
                if (debug) System.out.println("9 i sent this to the server"+encryptedServerNonce);
                
                 //recieve key
				byte [] finaltoken= new byte[inStream.available()];
				inStream.read(finaltoken);
				byte[]  finaltokendec =decAESsessionCipher.doFinal(finaltoken);
				if (debug) System.out.println("10 final step"+new String(finaltokendec));

            } catch (IOException e) {
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
            } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }

        // This method sets decAESsessioncipher & encAESsessioncipher
        private void calculateSessionKey(PrivateKey y, PublicKey gToTheX) {

            try {
                // Find g^xy
                KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
                serverKeyAgree.init(y);
                serverKeyAgree.doPhase(gToTheX, true);
                byte[] secretDH = serverKeyAgree.generateSecret();
                // Use first 16 bytes of g^xy to make an AES key
                byte[] aesSecret = new byte[16];
                System.arraycopy(secretDH, 0, aesSecret, 0, 16);
                Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
                // Set up Cipher Objects
                decAESsessionCipher = Cipher.getInstance("AES");
                decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
                encAESsessionCipher = Cipher.getInstance("AES");
                encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);

            } catch (NoSuchAlgorithmException e) {
                System.out.println(e);
            } catch (InvalidKeyException e) {
                System.out.println(e);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
        }

}

    public static class ProtocolClientInstance1 {

        Socket socket;
        boolean debug = true;
        // int i ;
        // boolean hacking;
        byte[] serverNonce = new byte[4];
        static Cipher decAESsessionCipher;
        static Cipher encAESsessionCipher;
        public byte[] clientNonceKey;

        public ProtocolClientInstance1(Socket socket) {
            this.socket = socket;
            // hacking = false;
        }

        // this one will take in the encrypted nonce+1 and it will run normally
        public ProtocolClientInstance1(Socket socket, byte[] serverNonce) {
            this.socket = socket;
            // hacking = true;
            this.serverNonce = serverNonce;

        }

        public void run() {
            DataOutputStream outStream;
            DataInputStream inStream;
            try {
                outStream = new DataOutputStream(socket.getOutputStream());
                inStream = new DataInputStream(socket.getInputStream());

                // Use crypto API to calculate y & g^y
                DHParameterSpec dhSpec = new DHParameterSpec(p, g);
                KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
                diffieHellmanGen.initialize(dhSpec);
                KeyPair serverPair = diffieHellmanGen.generateKeyPair();
                PrivateKey y = serverPair.getPrivate();
                PublicKey gToTheY = serverPair.getPublic();

                //
                // Protocol message 1
                outStream.writeInt(gToTheY.getEncoded().length);
                outStream.write(gToTheY.getEncoded());

                // Protocol message 2
                int publicKeyLen = inStream.readInt();
                byte[] message1 = new byte[publicKeyLen];
                inStream.read(message1);
                KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
                PublicKey gToTheX = keyfactoryDH.generatePublic(x509Spec);

                // Calculate session key
                calculateSessionKey(y, gToTheX);

                if (debug)
                    System.out.println("4 i got this from client 1" + serverNonce);

                // send the encrypted nonce to the server (protocol 3)
                byte[] encryptedClientNonce = encAESsessionCipher.doFinal(serverNonce);
                outStream.write(encryptedClientNonce);
                if (debug)
                    System.out.println("5 i sent this to get key encrytion " + encryptedClientNonce);

                // Protocol Step 4
                byte[] message5ct = new byte[32];
                inStream.read(message5ct);
                byte[] deccryptedServerNonce = decAESsessionCipher.doFinal(message5ct);
                clientNonceKey = new byte[16];
                System.arraycopy(deccryptedServerNonce, 0, clientNonceKey, 0, 16);
                if (debug)
                    System.out.println("6 i client2 got this from server " + deccryptedServerNonce);
                if (debug)
                    System.out.println("7 this is what i will send to the client1" + clientNonceKey);
                socket.close();

            } catch (IOException e) {
                // Nothing we can do about this one
                if (debug)
                    System.out.println("Your wi-fi sucks: " + e);
                return;
            } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (BadPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        public  byte[] getClientEncKey() {
            return clientNonceKey;
        }

        private void calculateSessionKey(PrivateKey y, PublicKey gToTheX)  {
            try {
            // Find g^xy
            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            serverKeyAgree.init(y);
            serverKeyAgree.doPhase(gToTheX, true);
            byte[] secretDH = serverKeyAgree.generateSecret();
            //Use first 16 bytes of g^xy to make an AES key
            byte[] aesSecret = new byte[16];
            System.arraycopy(secretDH,0,aesSecret,0,16);
            Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
            // Set up Cipher Objects
            decAESsessionCipher = Cipher.getInstance("AES");
            decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
            encAESsessionCipher = Cipher.getInstance("AES");
            encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
            } catch (NoSuchAlgorithmException e ) {
            System.out.println(e);
            } catch (InvalidKeyException e) {
            System.out.println(e);
            } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            }
        }
    }
     
}