package pt.ulisboa.tecnico.meic.sec.lib;

import org.apache.commons.lang3.tuple.ImmutablePair;
import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.MessageNotFreshException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.TreeMap;

public class PwdManagerClient {

    private static final int BYTES_IV = 16;
    private static final String IV_HASH_DAT = "ivhash.dat";

    private transient KeyStore keyStore;
    private transient String asymAlias;
    private transient char[] asymPwd;
    private transient String symAlias;
    private transient char[] symPwd;

    private TreeMap<ImmutablePair<String,String>, byte[]> ivMap;
    private CryptoManager cryptoManager;
    private ServerCalls call;

    public String helloWorld() {
        return "Hello World. I'm a Password Manager Client";
    }

    public void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd) throws NoSuchAlgorithmException {
        this.keyStore = keyStore;
        this.asymAlias = asymAlias;
        this.asymPwd = asymPwd;
        this.symAlias = symAlias;
        this.symPwd = symPwd;
        // Pick type of ServerCalls
        call = new SingleServerCalls();
        cryptoManager = new CryptoManager();
        loadIvs();
    }


    // Only for JUnit
    void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd, ServerCalls serverCalls) throws NoSuchAlgorithmException {
        init(keyStore, asymAlias, asymPwd, symAlias, symPwd);
        call = serverCalls;
        ivMap = new TreeMap<>();
    }

    public void register_user() throws RemoteServerInvalidResponseException {
        PublicKey publicKey = null;
        try {
            publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String publicKeyB64 = cryptoManager.convertBinaryToBase64(publicKey.getEncoded());
            User user = new User(publicKeyB64, cryptoManager.convertBinaryToBase64(signFields(new String[]{publicKeyB64})));
            call.register(user);
        } catch (RemoteServerInvalidResponseException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | SignatureException | IOException e) {
            e.printStackTrace();
        }
    }

    public void save_password(String domain, String username, String password) throws RemoteServerInvalidResponseException {
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

            call.putPassword(pwdToRegister);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException |
                IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException |
                IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
    }

    public String retrieve_password(String domain, String username) throws RemoteServerInvalidResponseException, ServersIntegrityException, ServersSignatureNotValidException {
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
                    retrieveIV(domain, username),
                    Cipher.DECRYPT_MODE);
            decryptedPwd = new String(decryptedBytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException |
                InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException |
                NoSuchPaddingException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
        return decryptedPwd;
    }

    public void close(){
        Thread t = new Thread(() -> {
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(IV_HASH_DAT)))){
                out.writeObject(ivMap);
            }catch (IOException ex){
                ex.printStackTrace();
            }
        });
        t.start();
        keyStore = null;
        asymAlias = null;
        asymPwd = null;
        symAlias = null;
        symPwd = null;
        try {
            t.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    //Necessary to Mockup
    protected void setServerCalls(ServerCalls serverCalls){
        this.call = serverCalls;
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
                            retrieveIV(domain, username),
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    private byte[] retrieveIV(String domain, String username) throws NoSuchAlgorithmException {
        ImmutablePair<String, String> key = new ImmutablePair<>(domain, username);
        if(ivMap.containsKey(key)) return ivMap.get(key);
        else {
            byte[] iv = cryptoManager.generateIV(BYTES_IV);
            ivMap.put(key, iv);
            return iv;
        }
    }

    private String[] encryptFields(String domain, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        String[] stuff = new String[]{domain, username};
        String[] encryptedStuff = new String[2];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                    cryptoManager.runAES(stuff[i].getBytes(),
                            CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                            retrieveIV(domain, username),
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    private void verifyFreshness(Password retrieved) {
        // Check Freshness
        boolean validTime = cryptoManager.isTimestampAndNonceValid(Timestamp.valueOf(retrieved.getTimestamp()),
                                                cryptoManager.convertBase64ToBinary(retrieved.getNonce()));
        if(!validTime) {
            //System.out.println("Message not fresh!");
            throw new MessageNotFreshException();
        }
    }

    private void verifyServersIntegrity(PublicKey publicKey, Password retrieved) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersIntegrityException {
        // Check tampering
        String[] myFields = new String[]{retrieved.getDomain(), retrieved.getUsername(), retrieved.getPassword()};
        boolean validSig = isValidSig(publicKey, myFields, retrieved.getPwdSignature());
        if(!validSig){
            //System.out.println("Content tampered with!");
            throw new ServersIntegrityException();
        }
    }

    private void verifyServersSignature(Password retrieved) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersSignatureNotValidException {
        String[] myFields = new String[]{retrieved.getPublicKey(),
                                            retrieved.getDomain(),
                                            retrieved.getUsername(),
                                            retrieved.getPassword(),
                                            retrieved.getPwdSignature(),
                                            retrieved.getTimestamp(),
                                            retrieved.getNonce()};

        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(retrieved.getPublicKey()))
        );

        final boolean validSig = isValidSig(serverPublicKey, myFields, retrieved.getReqSignature());
        if(!validSig) {
            //System.out.println("Message not authenticated!");
            throw new ServersSignatureNotValidException();
        }
    }

    private boolean isValidSig(PublicKey serverPublicKey, String[] myFields, String reqSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.isValidSig(serverPublicKey, myFields, reqSignature);
    }

    private void loadIvs() throws NoSuchAlgorithmException {
        try (ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(IV_HASH_DAT)))){
            ivMap = (TreeMap<ImmutablePair<String,String>, byte[]>) in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage() + "\nStarting a new IV Table.");
            ivMap = new TreeMap<>();
        }
    }
}
