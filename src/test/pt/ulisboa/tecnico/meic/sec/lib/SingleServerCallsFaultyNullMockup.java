package pt.ulisboa.tecnico.meic.sec.lib;

import java.security.NoSuchAlgorithmException;

public class SingleServerCallsFaultyNullMockup extends SingleServerCallsMockup{
    public SingleServerCallsFaultyNullMockup() throws NoSuchAlgorithmException {
    }

    @Override
    public User register(User user) {
       return null;
    }

    @Override
    public Password putPassword(Password password) {
        return null;
    }

    @Override
    public Password retrievePassword(Password password) {
        return null;
    }
}
