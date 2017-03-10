package pt.ulisboa.tecnico.meic.sec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.sql.Timestamp;

public class PwdManagerClient {

    private KeyStore keyStore;
    private Key aesKey;
    private byte[] lastIV;
    private ServerCalls call;
    private CryptoManager cryptoManager;

    public String helloWorld() {
        return "Hello World. I'm a Password Manager Client";
    }

    public void init(KeyStore keyStore) throws NoSuchAlgorithmException {
        this.keyStore = keyStore;
        call = new ServerCalls();
        cryptoManager = new CryptoManager();
        getAesKeyReady();
    }

    private void getAesKeyReady() throws NoSuchAlgorithmException {
        try {
            aesKey = CryptoUtilities.readAESKey("aes.key");
        } catch (IOException e) {
            aesKey = cryptoManager.generateAESKey(128);
            new Thread(() -> {
                try {
                    CryptoUtilities.writeAESKey("aes.key", aesKey);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }).start();
        }
    }

    public void register_user(){
        PublicKey publicKey = null;
        try {
            publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, "aa", "aa".toCharArray());
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        User user = new User(cryptoManager.convertBinaryToBase64(publicKey.getEncoded()));
        try {
            call.register(user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void save_password(String domain, String username, String password){
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, "aa", "aa".toCharArray());
            lastIV = cryptoManager.generateIV(16);
            String[] encryptedStuff = encryptFields(domain, username, password);

            Password pwdToRegister = new Password(
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    encryptedStuff[2], // password
                    "SIGN1",
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
                    cryptoManager.convertBinaryToBase64(lastIV),
                    "SIGN2"
            );
            call.putPassword(pwdToRegister);
        }catch (Exception e){
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
    }

    private String[] encryptFields(String domain, String username, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String[] stuff = new String[]{domain, username, password};
        String[] encryptedStuff = new String[3];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                            cryptoManager.runAES(stuff[i].getBytes(),
                            aesKey,
                            lastIV,
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    private String[] encryptFields(String domain, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String[] stuff = new String[]{domain, username};
        String[] encryptedStuff = new String[2];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                    cryptoManager.runAES(stuff[i].getBytes(),
                            aesKey,
                            lastIV,
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    public String retrieve_password(String domain, String username){
        String decryptedPwd = "";
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, "aa", "aa".toCharArray());
            String[] encryptedStuff = encryptFields(domain, username);
            Password pwdToRetrieve = new Password(
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0],
                    encryptedStuff[1],
                    "SIGN1", // not sure if this is needed
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
                    cryptoManager.convertBinaryToBase64(lastIV),
                    "SIGN2"
            );
            Password retrieved = call.retrievePassword(pwdToRetrieve);
            // verify signature here
            boolean valid = cryptoManager.isTimestampAndNonceValid(Timestamp.valueOf(retrieved.getTimestamp()),
                                                    cryptoManager.convertBase64ToBinary(retrieved.getNonce()));
            if(!valid) System.out.println("Message not fresh!");
            byte[] decryptedBytes = cryptoManager.runAES(cryptoManager.convertBase64ToBinary(retrieved.getPassword()),
                                aesKey,
                                lastIV,
                                Cipher.DECRYPT_MODE);
            decryptedPwd = new String(decryptedBytes);

        }catch (Exception e){
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
        return decryptedPwd;
    }

    public void close(){

    }
}
