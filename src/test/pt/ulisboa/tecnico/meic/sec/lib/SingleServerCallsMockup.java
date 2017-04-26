package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.lib.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.InvalidRequestSignatureException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

public class SingleServerCallsMockup extends SingleServerCalls{
    protected CryptoManager cryptoManager;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private HashMap<String, Password> passwordStorage;

    public SingleServerCallsMockup() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        cryptoManager = new CryptoManager();
        passwordStorage = new HashMap<>();
    }

    @Override
    public User register(User user) {
        return user;
    }

    @Override
    public Password putPassword(Password password) {
        try{
            verifyPasswordInsertSignature(password);
            passwordStorage.put(password.domain+password.username, password);
            return getPasswordReadyToSend(password);

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | InvalidKeySpecException |
                ExpiredTimestampException | InvalidRequestSignatureException |InvalidPasswordSignatureException |
                DuplicateRequestException e) {
            return null;
        }
    }

    @Override
    public Password retrievePassword(Password password) {
        try{
            verifyPasswordFetchSignature(password);

            Password pwd = passwordStorage.get(password.getDomain() + password.getUsername());
            if(pwd == null ||  !password.getPublicKey().equals(pwd.getPublicKey()))
                return null;

            return getPasswordReadyToSend(pwd);
        } catch (ExpiredTimestampException | NoSuchAlgorithmException | DuplicateRequestException |
                SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            return null;
        }
    }

    private byte[] signFields(String[] fieldsToSend) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.signFields(fieldsToSend, privateKey);
    }

    private void verifyPasswordInsertSignature(final Password password) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidPasswordSignatureException, InvalidRequestSignatureException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));

        String[] myFields = new String[]{
                password.publicKey,
                password.domain,
                password.username,
                password.password,
                password.pwdSignature,
                password.timestamp,
                password.nonce
        };

        cryptoManager.isValidSig(publicKey, myFields, password.reqSignature);
        verifyFreshness(password.nonce, password.timestamp);
    }

    private void verifyFreshness(String nonce, String timestamp) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        if(!cryptoManager.isTimestampAndNonceValid(new java.sql.Timestamp(Long.valueOf(timestamp)),
                cryptoManager.convertBase64ToBinary(nonce))){
            throw new ExpiredTimestampException();
        }
    }

    private Password getPasswordReadyToSend(final Password pwd) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Password password = new Password(pwd.getPublicKey(), pwd.getDomain(), pwd.getUsername(), pwd.getPassword(),
                pwd.getVersionNumber(), pwd.getDeviceId(), pwd.getPwdSignature(), pwd.getTimestamp(),
                pwd.getNonce(), pwd.getReqSignature());

        password.publicKey = cryptoManager.convertBinaryToBase64(publicKey.getEncoded());
        password.timestamp = String.valueOf(cryptoManager.getActualTimestamp().getTime());
        password.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));

        String[] fieldsToSend = new String[]{
                password.publicKey,
                password.domain,
                password.username,
                password.password,
                password.versionNumber,
                password.pwdSignature,
                password.timestamp,
                password.nonce,
        };

        password.reqSignature = cryptoManager.convertBinaryToBase64(signFields(fieldsToSend));
        return password;
    }

    private void verifyPasswordFetchSignature(final Password password) throws DuplicateRequestException, NoSuchAlgorithmException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));

        String[] myFields = new String[]{
                password.publicKey,
                password.domain,
                password.username,
                password.timestamp,
                password.nonce
        };

        cryptoManager.isValidSig(publicKey, myFields, password.reqSignature);
        verifyFreshness(password.nonce, password.timestamp);
    }
}
