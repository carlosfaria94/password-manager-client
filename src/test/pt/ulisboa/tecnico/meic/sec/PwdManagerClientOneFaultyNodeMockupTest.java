package pt.ulisboa.tecnico.meic.sec;

import org.junit.After;
import org.junit.Before;
import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;
import pt.ulisboa.tecnico.meic.sec.lib.ServerCallsPoolMockup;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class PwdManagerClientOneFaultyNodeMockupTest extends PwdManagerClientTest {

    public PwdManagerClientOneFaultyNodeMockupTest() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
        client = new PwdManagerClient();
        ServerCallsPoolMockup pool = new ServerCallsPoolMockup(3, 1);


        KeyStore ks = CryptoUtilities.readKeystoreFile("keystore.jceks", KEYSTORE_PASSWORD.toCharArray());
        client.init(ks, "asymm", KEYSTORE_PASSWORD.toCharArray(), "symm", KEYSTORE_PASSWORD.toCharArray(), pool);
        client.register_user();
    }

    @Before
    @Override
    public void setUp() {
    }

    @Override
    @After
    public void tearDown() {
    }
}
