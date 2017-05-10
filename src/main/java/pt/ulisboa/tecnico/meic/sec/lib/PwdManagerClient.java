package pt.ulisboa.tecnico.meic.sec.lib;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.*;

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

    private static final int BYTES_IV = 16;
    private static final String UUID_DAT = "uuid.dat";

    private transient KeyStore keyStore;
    private transient String asymAlias;
    private transient char[] asymPwd;
    private transient String symAlias;
    private transient char[] symPwd;

    private TreeMap<ImmutablePair<String, String>, byte[]> ivCache;
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
        ivCache = new TreeMap<>();
        loadDeviceId();
    }

    private void loadDeviceId() {
        try (ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(UUID_DAT)))) {
            myDeviceId = (UUID) in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            System.err.println("Generating a new UUID random.");
            myDeviceId = UUID.randomUUID();
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(UUID_DAT)))) {
                out.writeObject(myDeviceId);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    public void register_user() {
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String publicKeyB64 = cryptoManager.convertBinaryToBase64(publicKey.getEncoded());
            User user = new User(publicKeyB64, cryptoManager.convertBinaryToBase64(signFields(new String[]{publicKeyB64})));

            call.register(user);

        } catch (UnrecoverableKeyException | NoSuchAlgorithmException
                | KeyStoreException | InvalidKeyException | SignatureException | IOException e) {
            e.printStackTrace();
        }
    }

    public void save_password(String domain, String username, String password) {
        save_password(domain, username, password, true);
        ivCache.remove(new ImmutablePair<>(domain, username));
    }

    private void save_password(String domain, String username, String password, boolean versionInc) {
        try {
            PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            String[] encryptedStuff = encryptFields(domain, username, password);

            LocalPassword lastPut;
            int version;
            try {
                lastPut = retrieve_password(domain, username);
                version = lastPut.getVersion();
            }catch (AllNullException e){
                version = 1;
                versionInc = false;
            }


            if (versionInc) {
                version++;
            }

            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    encryptedStuff[0], // domain
                    encryptedStuff[1], // username
                    encryptedStuff[2], // password
                    String.valueOf(version), // versionNumber
                    myDeviceId.toString(), // deviceId
                    cryptoManager.convertBinaryToBase64(signFields(
                            ArrayUtils.addAll(encryptedStuff, String.valueOf(version),
                                    myDeviceId.toString()))), //pwdSignature
                    String.valueOf(cryptoManager.getActualTimestamp().getTime()), //timestamp
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)) //nonce
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
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend)) //reqSignature
            );

            Password result = call.putPassword(pwdToRegister);

            // If any response is insecure, we delete it.
            verifyEverything(publicKey, result);
            System.out.println(result);

            // We tried our best to put a password, let's check if it really is there
            retrieve_password(domain, username);


        } catch (Exception e) {
        }
    }

    public LocalPassword retrieve_password(String domain, String username)
            throws NotEnoughResponsesConsensusException, AllNullException {
        LocalPassword password = null;
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
                    fieldsToSend[4], // timestamp
                    fieldsToSend[5], // nonce
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );

            Password[] retrieved = call.retrievePassword(pwdToRetrieve);

            ArrayList<LocalPassword> decipheredData = new ArrayList<>();
            // If any response is insecure, we delete it.
            for (int i = 0; i < retrieved.length; i++) {
                Password p = retrieved[i];
                if (p != null) {
                    try {
                        System.out.println(p);
                        verifyEverything(publicKey, p);
                        String[] fields = decipherFields(domain, username, p);
                        decipheredData.add(new LocalPassword(fields[0], fields[1], fields[2], fields[3], fields[4]));
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | SignatureException |
                            InvalidKeyException | ServersSignatureNotValidException | MessageNotFreshException |
                            ServersIntegrityException e) {
                        System.err.println(e.getMessage());
                        retrieved[i] = null;
                    }
                }
            }

            if(isAllNull(retrieved)) throw new AllNullException();
            else if (!enoughResponses(retrieved)) throw new NotEnoughResponsesConsensusException();

            LocalPassword[] localPasswordArray = sortForMostRecentPassword(decipheredData);
            //updateLocalPasswordVersion(localPasswordArray[0]);

            // Atomic (1, N) Register
            // If there are version inconsistencies
            if (localPasswordArray[localPasswordArray.length - 1].getVersion() != localPasswordArray[0].getVersion()) {
                save_password(localPasswordArray[0].getDomain(), localPasswordArray[0].getUsername(),
                        localPasswordArray[0].getPassword(), false);
            }
            password = localPasswordArray[0];

            ivCache.remove(new ImmutablePair<>(domain, username));

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | KeyStoreException |
                NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException |
                IllegalBlockSizeException | BadPaddingException |
                NoSuchPaddingException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return password;
    }

    public void close() {
        keyStore = null;
        asymAlias = null;
        asymPwd = null;
        symAlias = null;
        symPwd = null;
    }

    private void verifyEverything(PublicKey publicKey, Password p)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            ServersSignatureNotValidException, ServersIntegrityException, MessageNotFreshException {
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

    private String[] decipherFields(String domain, String username, Password p) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException, SignatureException, IOException, InvalidKeySpecException {
        return new String[]{
                new String(decipherField(domain, username, p.getDomain())),
                new String(decipherField(domain, username, p.getUsername())),
                new String(decipherField(domain, username, p.getPassword())),
                p.getVersionNumber(),
                p.getDeviceId()};
    }

    private byte[] decipherField(String domain, String username, String field)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException,
            KeyStoreException, SignatureException, IOException, InvalidKeySpecException {
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

    private boolean isAllNull(Object[] array) {
        int count = 0;
        for (Object o : array) if (o == null) count++;
        return count == array.length;
    }

    private byte[] signFields(String[] fieldsToSend)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException,
            SignatureException {
        return cryptoManager.signFields(fieldsToSend, keyStore, asymAlias, asymPwd);
    }

    private String[] encryptFields(String domain, String username, String password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, SignatureException, IOException {

        byte[] iv = generateIv(domain, username); // this initializes the versionNumber if needed.

        String[] stuff = new String[]{
                domain,
                username,
                password,
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

    private byte[] retrieveIV(String domain, String username) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, SignatureException, InvalidKeyException, IOException, InvalidKeySpecException {
        final ImmutablePair<String, String> immutablePair = new ImmutablePair<>(domain, username);
        if(ivCache.containsKey(immutablePair)){
            return ivCache.get(immutablePair);
        }
        else {
            String[] toSign = new String[]{
                    getHash(domain, username),
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64( cryptoManager.generateNonce(32))
            };
            IV iv = call.getIv(new IV(cryptoManager.convertBinaryToBase64(
                    CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd).getEncoded()),
                    toSign[0], toSign[1], toSign[2],  cryptoManager.convertBinaryToBase64(signFields(toSign))));
            byte[] iv2 = cryptoManager.convertBase64ToBinary(iv.getValue());
            ivCache.put(immutablePair, iv2);
            return iv2;
        }
    }


    private String getHash(String domain, String username) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(
                ArrayUtils.addAll(ArrayUtils.addAll(domain.getBytes(), username.getBytes())
                        , CryptoUtilities.getAESKeyFromKeystore(keyStore, symAlias, symPwd).getEncoded())));
    }

    private byte[] generateIv(String domain, String username) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, SignatureException, InvalidKeyException, IOException {
        byte[] iv = cryptoManager.generateIV(BYTES_IV);
        String[] toSign = new String[]{
                getHash(domain, username),
                cryptoManager.convertBinaryToBase64(iv),
                cryptoManager.getActualTimestamp().toString(),
                cryptoManager.convertBinaryToBase64( cryptoManager.generateNonce(32))
        };
        call.sendIv(new IV(cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd).getEncoded()),
                toSign[0], toSign[1], toSign[2], toSign[3],  cryptoManager.convertBinaryToBase64(signFields(toSign))));
        return iv;
    }

    private String[] encryptFields(String domain, String username)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException,
            KeyStoreException, SignatureException, IOException, InvalidKeySpecException {
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
        boolean validTime = cryptoManager.isTimestampAndNonceValid(
                new Timestamp(Long.valueOf(retrieved.getTimestamp())),
                cryptoManager.convertBase64ToBinary(retrieved.getNonce()));
        if (!validTime) {
            throw new MessageNotFreshException();
        }
    }

    private void verifyServersIntegrity(PublicKey publicKey, Password retrieved)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, ServersIntegrityException {
        // Check tampering
        String[] myFields = new String[]{retrieved.getDomain(), retrieved.getUsername(), retrieved.getPassword(),
                retrieved.getVersionNumber(), retrieved.getDeviceId()};
        boolean validSig = isValidSig(publicKey, myFields, retrieved.getPwdSignature());
        if (!validSig) {
            //System.out.println("Content tampered with!");
            throw new ServersIntegrityException();
        }
    }

    private void verifyServersSignature(Password retrieved)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            ServersSignatureNotValidException {
        String[] myFields = new String[]{retrieved.getPublicKey(),
                retrieved.getDomain(),
                retrieved.getUsername(),
                retrieved.getPassword(),
                retrieved.getVersionNumber(),
                retrieved.getDeviceId(),
                retrieved.getPwdSignature(),
                retrieved.getTimestamp(),
                retrieved.getNonce()};

        //System.out.println(retrieved);

        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(retrieved.getPublicKey()))
        );

        final boolean validSig = isValidSig(serverPublicKey, myFields, retrieved.getReqSignature());
        if (!validSig) {
            //System.out.println("Message not authenticated!");
            throw new ServersSignatureNotValidException();
        }
    }

    private boolean isValidSig(PublicKey serverPublicKey, String[] myFields, String reqSignature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.isValidSig(serverPublicKey, myFields, reqSignature);
    }

    private String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }

    // Only for JUnit
    public void init(KeyStore keyStore, String asymAlias, char[] asymPwd, String symAlias, char[] symPwd,
                     ServerCallsPool serverCalls) throws NoSuchAlgorithmException {
        init(keyStore, asymAlias, asymPwd, symAlias, symPwd);
        call = serverCalls;
        ivCache = new TreeMap<>();
    }
}
