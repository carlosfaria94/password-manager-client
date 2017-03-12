package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;

public final class PwdManagerClient {

    private static final int BYTES_IV = 16;
    private static final String IV_DAT = "iv.dat";

    private transient KeyStore keyStore;
    private transient String asymAlias;
    private transient char[] asymPwd;
    private transient String symAlias;
    private transient char[] symPwd;


    private Key aesKey;
    private byte[] lastIV;
    private ServerCalls call;
    private CryptoManager cryptoManager;

    public String helloWorld() {
        return "Hello World. I'm a Password Manager Client";
    }

    public void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd) throws NoSuchAlgorithmException {
        this.keyStore = keyStore;
        this.asymAlias = asymAlias;
        this.asymPwd = asymPwd;
        this.symAlias = symAlias;
        this.symPwd = symPwd;
        call = new ServerCalls();
        cryptoManager = new CryptoManager();
        lastIV = new byte[BYTES_IV];
        getIvReady();
    }

    public void register_user(){
        PublicKey publicKey = null;
        try {
            publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
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
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String[] encryptedStuff = encryptFields(domain, username, password);

            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    encryptedStuff[2], // password
                    cryptoManager.convertBinaryToBase64(signFields(encryptedStuff)),
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
                    cryptoManager.convertBinaryToBase64(lastIV),
            };
            Password pwdToRegister = new Password(
                    fieldsToSend[0],
                    fieldsToSend[1],
                    fieldsToSend[2],
                    fieldsToSend[3],
                    fieldsToSend[4],
                    fieldsToSend[5],
                    fieldsToSend[6],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );

            System.out.println(fieldsToSend[4]);

            System.out.println(cryptoManager.convertBinaryToBase64(signFields(fieldsToSend)));
            call.putPassword(pwdToRegister);
        }catch (Exception e){
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
    }

    private byte[] signFields(String[] fieldsToSend) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        return cryptoManager.signFields(fieldsToSend, keyStore, asymAlias, asymPwd);
    }

    private String[] encryptFields(String domain, String username, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        String[] stuff = new String[]{domain, username, password};
        String[] encryptedStuff = new String[3];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                            cryptoManager.runAES(stuff[i].getBytes(),
                            CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                            lastIV,
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    private String[] encryptFields(String domain, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        String[] stuff = new String[]{domain, username};
        String[] encryptedStuff = new String[2];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                    cryptoManager.runAES(stuff[i].getBytes(),
                            CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                            lastIV,
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    public String retrieve_password(String domain, String username){
        String decryptedPwd = "";
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String[] encryptedStuff = encryptFields(domain, username);

            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    cryptoManager.convertBinaryToBase64(signFields(encryptedStuff)),
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
                    cryptoManager.convertBinaryToBase64(lastIV),
            };

            Password pwdToRetrieve = new Password(
                    fieldsToSend[0],
                    fieldsToSend[1],
                    fieldsToSend[2],
                    fieldsToSend[3],
                    fieldsToSend[4],
                    fieldsToSend[5],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );

            Password retrieved = call.retrievePassword(pwdToRetrieve);
            verifyServersSignature(retrieved);
            verifyServersIntegrity(publicKey, retrieved);
            verifyFreshness(retrieved);

            // Finally, decrypting password.
            byte[] decryptedBytes = cryptoManager.runAES(cryptoManager.convertBase64ToBinary(retrieved.getPassword()),
                                CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                                lastIV,
                                Cipher.DECRYPT_MODE);
            decryptedPwd = new String(decryptedBytes);

        }catch (Exception e){
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
        return decryptedPwd;
    }

    private void verifyFreshness(Password retrieved) {
        // Check Freshness
        boolean validTime = cryptoManager.isTimestampAndNonceValid(Timestamp.valueOf(retrieved.getTimestamp()),
                                                cryptoManager.convertBase64ToBinary(retrieved.getNonce()));
        if(!validTime) {
            System.out.println("Message not fresh!");
            throw new RuntimeException("Message not fresh!");
        }
    }

    private void verifyServersIntegrity(PublicKey publicKey, Password retrieved) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Check tampering
        String[] myFields = new String[]{retrieved.getDomain(), retrieved.getUsername(), retrieved.getPassword()};
        boolean validSig = isValidSig(publicKey, myFields, retrieved.getPwdSignature());
        if(!validSig){
            System.out.println("Content tampered with!");
            throw new RuntimeException("Content tampered with!");
        }
    }

    private void verifyServersSignature(Password retrieved) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String[] myFields = new String[]{retrieved.getPublicKey(),
                                            retrieved.getDomain(),
                                            retrieved.getUsername(),
                                            retrieved.getPassword(),
                                            retrieved.getPwdSignature(),
                                            retrieved.getTimestamp(),
                                            retrieved.getNonce()};

        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(retrieved.getPublicKey())));

        final boolean validSig = isValidSig(serverPublicKey, myFields, retrieved.getReqSignature());
        if(!validSig) {
            System.out.println("Message not authenticated!");
            throw new RuntimeException("Message not authenticated!");
        }
    }

    private boolean isValidSig(PublicKey serverPublicKey, String[] myFields, String reqSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.isValidSig(serverPublicKey, myFields, reqSignature);
    }


    public void close(){

    }

    private void getIvReady() throws NoSuchAlgorithmException {
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(IV_DAT))){
            int readBytes = in.read(lastIV);
            //if(readBytes != -1) throw new IOException();
        } catch (IOException e) {
            e.printStackTrace();
            lastIV = cryptoManager.generateIV(BYTES_IV);
            new Thread(() -> {
                try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(IV_DAT))){
                    out.write(lastIV);
                }catch (IOException ex){
                    ex.printStackTrace();
                }
            }).start();
        }
    }
}
