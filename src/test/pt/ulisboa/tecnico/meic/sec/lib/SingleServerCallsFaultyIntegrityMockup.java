package pt.ulisboa.tecnico.meic.sec.lib;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SingleServerCallsFaultyIntegrityMockup extends SingleServerCallsMockup {
    public SingleServerCallsFaultyIntegrityMockup() throws NoSuchAlgorithmException {
        super();
    }

    @Override
    public User register(User user) {
        return null;
    }

    @Override
    public Password putPassword(Password password) {
        password = super.putPassword(password);

        if (password != null) {
            //Tamper password
            byte[] pwd = cryptoManager.convertBase64ToBinary(password.password);
            pwd[new SecureRandom().nextInt(pwd.length)] = 0x0;
            password.password = super.cryptoManager.convertBinaryToBase64(pwd);
        }

        return password;
    }

    @Override
    public Password retrievePassword(Password password) {
        password = super.retrievePassword(password);

        if (password != null) {
            //Tamper password
            byte[] pwd = cryptoManager.convertBase64ToBinary(password.password);
            pwd[new SecureRandom().nextInt(pwd.length)] = 0x0;
            password.password = super.cryptoManager.convertBinaryToBase64(pwd);
        }

        return password;
    }
}
