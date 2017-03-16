package pt.ulisboa.tecnico.meic.sec.lib;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Created by Bernardo on 16/03/2017.
 */
public class ServerCallsInvalidServersIntegrityMockup extends ServerCallsMockup {

    public ServerCallsInvalidServersIntegrityMockup() throws NoSuchAlgorithmException {
        super();
    }

    @Override
    public Password retrievePassword(Password pwd){
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

            //Tamper password
            fieldsToSend[3] = fieldsToSend[3].replace(fieldsToSend[3].charAt(1), 'A');

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
}
