package pt.ulisboa.tecnico.meic.sec.lib;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.MutablePair;
import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.MessageNotFreshException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.NotEnoughResponsesConsensusException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.*;

public class PwdManagerClient {

    private static final int INITIAL_VERSION = 0;
    private static final int BYTES_IV = 16;
    private static final String IV_HASH_DAT = "ivhash.dat";
    private static final String UUID_DAT = "uuid.dat";

    private transient KeyStore keyStore;
    private transient String asymAlias;
    private transient char[] asymPwd;
    private transient String symAlias;
    private transient char[] symPwd;

    private TreeMap<ImmutablePair<String, String>, MutablePair<byte[], Integer>> ivMap;
    private CryptoManager cryptoManager;
    private ServerCallsPool call;
    private UUID myDeviceId;

    public String helloWorld() {
        return "Hello World. I'm a Password Manager Client";
    }

    public void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd)
            throws NoSuchAlgorithmException {
        this.keyStore = keyStore;
        this.asymAlias = asymAlias;
        this.asymPwd = asymPwd;
        this.symAlias = symAlias;
        this.symPwd = symPwd;

        call = new ServerCallsPool();
        cryptoManager = new CryptoManager();
        loadIvs();
        loadDeviceId();
    }

    private void loadDeviceId() {
        try (ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(UUID_DAT)))) {
            myDeviceId = (UUID) in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage() + "\nGenerating UUID random.");
            myDeviceId = UUID.randomUUID();
        }
    }

    public void register_user() {
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String publicKeyB64 = cryptoManager.convertBinaryToBase64(publicKey.getEncoded());
            User user = new User(publicKeyB64, cryptoManager.convertBinaryToBase64(signFields(new String[]{publicKeyB64})));

            User[] retrieved = call.register(user);

            // If any response is insecure, we delete it.
            for (int i = 0; i < retrieved.length; i++) {
                User u = retrieved[i];
                if (u != null) {
                    try {
                        isValidFingerprint(publicKeyB64, u.getFingerprint());
                    } catch (NoSuchAlgorithmException e) {
                        retrieved[i] = null;
                    }
                }
            }

            if (!enoughResponses(retrieved)) throw new NotEnoughResponsesConsensusException();

        } catch (UnrecoverableKeyException | NoSuchAlgorithmException
                | KeyStoreException | InvalidKeyException | SignatureException | IOException e) {
            e.printStackTrace();
        }
    }

    public void save_password(String domain, String username, String password) {
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String[] encryptedStuff = encryptFields(domain, username, password);

            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    encryptedStuff[2], // password
                    encryptedStuff[3], // versionNumber
                    encryptedStuff[4], // deviceId
                    cryptoManager.convertBinaryToBase64(signFields(encryptedStuff)),
                    String.valueOf(cryptoManager.getActualTimestamp().getTime()),
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
                    fieldsToSend[7],
                    fieldsToSend[8],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );

            Password[] retrieved = call.putPassword(pwdToRegister);

            // If any response is insecure, we delete it.
            for (int i = 0; i < retrieved.length; i++) {
                Password p = retrieved[i];
                if (p != null) {
                    try {
                        verifyEverything(publicKey, p);
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | SignatureException |
                            InvalidKeyException | ServersSignatureNotValidException|
                            ServersIntegrityException | MessageNotFreshException e) {
                        retrieved[i] = null;
                    }
                }
            }

            if (!enoughResponses(retrieved)) throw new NotEnoughResponsesConsensusException();

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException |
                IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException |
                IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
    }

    public String retrieve_password(String domain, String username) throws ServersIntegrityException, ServersSignatureNotValidException {
        String password = "";
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String[] encryptedStuff = encryptFields(domain, username);

            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    cryptoManager.convertBinaryToBase64(signFields(encryptedStuff)),
                    String.valueOf(cryptoManager.getActualTimestamp().getTime()),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
            };

            Password pwdToRetrieve = new Password(
                    fieldsToSend[0], // pubKey
                    fieldsToSend[1], // domain
                    fieldsToSend[2], // username
                    fieldsToSend[3], // pwdSignature
                    fieldsToSend[4],
                    fieldsToSend[5],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );

            Password[] retrieved = call.retrievePassword(pwdToRetrieve);

            ArrayList<LocalPassword> decipheredData = new ArrayList<>();
            // If any response is insecure, we delete it.
            for (int i = 0; i < retrieved.length; i++) {
                Password p = retrieved[i];
                if (p != null) {
                    try {
                        verifyEverything(publicKey, p);
                        String[] fields = decipherFields(domain, username, p);
                        decipheredData.add(new LocalPassword(fields[0], fields[1], fields[2], fields[3], fields[4]));
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | SignatureException |
                            InvalidKeyException | ServersSignatureNotValidException
                            | MessageNotFreshException e) {
                        retrieved[i] = null;
                    }
                }
            }

            if (!enoughResponses(retrieved)) throw new NotEnoughResponsesConsensusException();

            LocalPassword[] localPasswordArray = sortForMostRecentPassword(decipheredData);
            updateLocalPasswordVersion(localPasswordArray[0]);
            // ver se houve processos diferentes
            // Atomic (1, N) Register
            // #writeYourReads
            if(localPasswordArray[localPasswordArray.length - 1].getVersion() != localPasswordArray[0].getVersion())
                save_password(localPasswordArray[0].getDomain(), localPasswordArray[0].getUsername(),
                        localPasswordArray[0].getPassword());

            password = localPasswordArray[0].getPassword();

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException |
                IllegalBlockSizeException | BadPaddingException |
                NoSuchPaddingException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        }
        return password;
    }

    public void close() {
        Thread t = new Thread(() -> {
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(IV_HASH_DAT)))) {
                out.writeObject(ivMap);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        Thread t2 = new Thread(() -> {
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(UUID_DAT)))) {
                out.writeObject(myDeviceId);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        t.start();
        t2.start();
        keyStore = null;
        asymAlias = null;
        asymPwd = null;
        symAlias = null;
        symPwd = null;
        try {
            t.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void verifyEverything(PublicKey publicKey, Password p) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersSignatureNotValidException, ServersIntegrityException, MessageNotFreshException {
        verifyServersSignature(p);
        verifyFreshness(p);
        verifyServersIntegrity(publicKey, p);
    }

    private LocalPassword[] sortForMostRecentPassword(ArrayList<LocalPassword> decipheredData) {
        // Sort to get the most recent version
        LocalPassword[] array = new LocalPassword[decipheredData.size()];
        array = decipheredData.toArray(array);
        Arrays.sort(array);
        return array;
    }

    private void updateLocalPasswordVersion(LocalPassword localPassword) {
        if(localPassword.getVersion() > getVersion(localPassword.getDomain(), localPassword.getUsername())){
            System.out.println("Server version is greater than the client. This can occur in a sync problem. " +
                    "Do you want to update your version records? [Y/n]");
            Scanner scanner = new Scanner(System.in);
            if(scanner.nextLine().equalsIgnoreCase("y")){
                setVersion(localPassword.getDomain(), localPassword.getUsername(), localPassword.getVersion());
                System.out.println("Version updated!");
            } else if (scanner.nextLine().equalsIgnoreCase("n")) {
                System.out.println("Skip updated!");
            } else
                System.out.println("Assuming default: Skip Update");
        }else
            setVersion(localPassword.getDomain(), localPassword.getUsername(), localPassword.getVersion());
        System.out.println("Password Selected:\n" + localPassword);
    }

    private String[] decipherFields(String domain, String username, Password p) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        return new String[]{
                new String(decipherField(domain, username, p.getDomain())),
                new String(decipherField(domain, username, p.getUsername())),
                new String(decipherField(domain, username, p.getPassword())),
                new String(decipherField(domain, username, p.getVersionNumber())),
                new String(decipherField(domain, username, p.getDeviceId()))};
    }

    private byte[] decipherField(String domain, String username, String field) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        return cryptoManager.runAES(cryptoManager.convertBase64ToBinary(field),
                CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                retrieveIV(domain, username),
                Cipher.DECRYPT_MODE);
    }

    private boolean enoughResponses(Object[] retrieved) {
        int n = call.size();
        /* If there were more responses than the number of faults we tolerate, then we will proceed.
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        return countNotNull(retrieved) > (2.0 / 3.0) * n - 1.0 / 6.0;
    }

    private int countNotNull(Object[] array) {
        int count = 0;
        for (Object o : array) if (o != null) count++;
        return count;
    }

    private byte[] signFields(String[] fieldsToSend) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        return cryptoManager.signFields(fieldsToSend, keyStore, asymAlias, asymPwd);
    }

    private String[] encryptFields(String domain, String username, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        byte[] iv = retrieveIV(domain, username); // this initializes the versionNumber if needed.
        int version = getVersion(domain, username) + 1;
        setVersion(domain, username, version);

        String[] stuff = new String[]{
                domain,
                username,
                password,
                String.valueOf(version),
                myDeviceId.toString()
        };

        String[] encryptedStuff = new String[stuff.length];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                    cryptoManager.runAES(
                            stuff[i].getBytes(),
                            CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                            iv,
                            Cipher.ENCRYPT_MODE
                    ));
        }

        return encryptedStuff;
    }

    private int getVersion(String domain, String username) {
        return ivMap.get(new ImmutablePair<>(domain, username)).getRight();
    }

    private void setVersion(String domain, String username, int version) {
        ivMap.get(new ImmutablePair<>(domain, username)).setRight(version);
    }

    private byte[] retrieveIV(String domain, String username) throws NoSuchAlgorithmException {
        ImmutablePair<String, String> key = new ImmutablePair<>(domain, username);
        if (ivMap.containsKey(key)) return ivMap.get(key).getLeft();
        else {
            byte[] iv = cryptoManager.generateIV(BYTES_IV);
            ivMap.put(key, new MutablePair<>(iv, INITIAL_VERSION));
            return iv;
        }
    }

    private String[] encryptFields(String domain, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException {
        byte[] iv = retrieveIV(domain, username);
        String[] stuff = new String[]{domain, username};
        String[] encryptedStuff = new String[stuff.length];
        for (int i = 0; i < stuff.length && i < encryptedStuff.length; i++) {
            encryptedStuff[i] = cryptoManager.convertBinaryToBase64(
                    cryptoManager.runAES(stuff[i].getBytes(),
                            CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd),
                            iv,
                            Cipher.ENCRYPT_MODE));
        }
        return encryptedStuff;
    }

    private void verifyFreshness(Password retrieved) throws MessageNotFreshException {
        // Check Freshness
        boolean validTime = cryptoManager.isTimestampAndNonceValid(new Timestamp(Long.valueOf(retrieved.getTimestamp())),
                cryptoManager.convertBase64ToBinary(retrieved.getNonce()));
        if (!validTime) {
            throw new MessageNotFreshException();
        }
    }

    private void verifyServersIntegrity(PublicKey publicKey, Password retrieved) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersIntegrityException {
        // Check tampering
        String[] myFields = new String[]{retrieved.getDomain(), retrieved.getUsername(), retrieved.getPassword(),
                retrieved.getVersionNumber()};
        boolean validSig = isValidSig(publicKey, myFields, retrieved.getPwdSignature());
        if (!validSig) {
            //System.out.println("Content tampered with!");
            throw new ServersIntegrityException();
        }
    }

    private void verifyServersSignature(Password retrieved) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersSignatureNotValidException {
        String[] myFields = new String[]{retrieved.getPublicKey(),
                retrieved.getDomain(),
                retrieved.getUsername(),
                retrieved.getPassword(),
                retrieved.getVersionNumber(),
                retrieved.getPwdSignature(),
                retrieved.getTimestamp(),
                retrieved.getNonce()};

        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(retrieved.getPublicKey()))
        );

        final boolean validSig = isValidSig(serverPublicKey, myFields, retrieved.getReqSignature());
        if (!validSig) {
            //System.out.println("Message not authenticated!");
            throw new ServersSignatureNotValidException();
        }
    }

    private boolean isValidSig(PublicKey serverPublicKey, String[] myFields, String reqSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.isValidSig(serverPublicKey, myFields, reqSignature);
    }

    private String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }

    private boolean isValidFingerprint(String publicKey, String receivedFingerprint) throws NoSuchAlgorithmException {
        return this.generateFingerprint(publicKey).equals(receivedFingerprint);
    }

    private void loadIvs() throws NoSuchAlgorithmException {
        try (ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(IV_HASH_DAT)))) {
            ivMap = (TreeMap<ImmutablePair<String, String>, MutablePair<byte[], Integer>>) in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage() + "\nStarting a new IV Table.");
            ivMap = new TreeMap<>();
        }
    }

    // Only for JUnit
    void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd,
              SingleServerCalls serverCalls) throws NoSuchAlgorithmException {
        init(keyStore, asymAlias, asymPwd, symAlias, symPwd);
        //call = serverCalls;
        ivMap = new TreeMap<>();
    }

    // Necessary to Mockup
    protected void setServerCalls(SingleServerCalls serverCalls) {
        //this.call = serverCalls;
    }
}
