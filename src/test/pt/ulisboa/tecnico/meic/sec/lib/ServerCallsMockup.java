package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import java.security.*;
import java.util.HashMap;

public class ServerCallsMockup extends ServerCalls {
    protected CryptoManager cryptoManager;
    protected PublicKey publicKey;
    protected PrivateKey privateKey;

    protected HashMap<String, String> passwords = new HashMap<>();
    protected HashMap<String, String> pwdSignatures = new HashMap<>();

    public ServerCallsMockup() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        cryptoManager = new CryptoManager();
    }

    protected byte[] signFields (String[] fieldsToSend) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return cryptoManager.signFields(fieldsToSend, privateKey);
    }

    @Override
    public User register(User user) {
        return user;
    }

    @Override
    public Password putPassword(Password pwd) {
        passwords.put(pwd.getDomain()+pwd.getUsername(), pwd.getPassword());
        pwdSignatures.put(pwd.getDomain()+pwd.getUsername(), pwd.getPwdSignature());
        try {
            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    pwd.getDomain(), // domain
                    pwd.getUsername(), // username
                    pwd.getPassword(), // password
                    pwd.getPwdSignature(),
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
            };

            return new Password(
                    fieldsToSend[0],
                    fieldsToSend[1],
                    fieldsToSend[2],
                    fieldsToSend[3],
                    fieldsToSend[4],
                    fieldsToSend[5],
                    fieldsToSend[6],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public Password retrievePassword(Password pwd) {
        try {
            String[] fieldsToSend = new String[]{
                    cryptoManager.convertBinaryToBase64(publicKey.getEncoded()),
                    pwd.getDomain(), // domain
                    pwd.getUsername(), // username
                    passwords.get(pwd.getDomain() + pwd.getUsername()), // password
                    pwdSignatures.get(pwd.getDomain() + pwd.getUsername()), // password signature
                    cryptoManager.getActualTimestamp().toString(),
                    cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32)),
            };

            pwd = new Password(
                    fieldsToSend[0],
                    fieldsToSend[1],
                    fieldsToSend[2],
                    fieldsToSend[3],
                    fieldsToSend[4],
                    fieldsToSend[5],
                    fieldsToSend[6],
                    cryptoManager.convertBinaryToBase64(signFields(fieldsToSend))
            );
            return pwd;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }
}
