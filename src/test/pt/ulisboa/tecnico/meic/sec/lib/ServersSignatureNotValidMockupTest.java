package pt.ulisboa.tecnico.meic.sec.lib;

import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;


public class ServersSignatureNotValidMockupTest extends TestCase {
    private static final String BATATA = "batata";
    private PwdManagerClient pwdManagerClient;
    private ServerCallsInvalidServersSignatureMockup server;

    @Before
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, RemoteServerInvalidResponseException, SignatureException, NoSuchProviderException, InvalidKeyException {
        pwdManagerClient = new PwdManagerClient();
        server = new ServerCallsInvalidServersSignatureMockup();

        KeyStore ks = CryptoUtilities.readKeystoreFile("keystore.jceks", BATATA.toCharArray());
        pwdManagerClient.init(ks, "asymm", BATATA.toCharArray(), "symm", BATATA.toCharArray(), server);
        pwdManagerClient.register_user();
    }

    @After
    public void tearDown() {
        pwdManagerClient.close();
    }

    @Test(expected = ServersSignatureNotValidException.class)
    public void testServersSignatureNotValid() throws RemoteServerInvalidResponseException {

        pwdManagerClient.save_password("youtube.com", "unicornio", "arcoiris");
        try {
            String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
            fail("Devia falhar aqui");
        } catch (ServersIntegrityException e) {
            fail("Devia falhar aqui");
        } catch (ServersSignatureNotValidException e) {

        }
    }
}