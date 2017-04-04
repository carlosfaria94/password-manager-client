package pt.ulisboa.tecnico.meic.sec.lib;

import java.security.*;

/**
 * Created by Bernardo on 16/03/2017.
 */
public class SingleServerCallsInvalidServersSignatureMockup extends SingleServerCallsMockup {

    public SingleServerCallsInvalidServersSignatureMockup() throws NoSuchAlgorithmException {
        super();
    }

    @Override
    public Password retrievePassword(Password pwd){
        //Change password byte
        pwd = super.retrievePassword(pwd);
        byte[] password = super.cryptoManager.convertBase64ToBinary(pwd.password);
        password[1] = 0x0;
        pwd.password = super.cryptoManager.convertBinaryToBase64(password);
        return pwd;
    }
}
