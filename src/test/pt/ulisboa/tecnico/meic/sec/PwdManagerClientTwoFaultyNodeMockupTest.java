package pt.ulisboa.tecnico.meic.sec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;
import pt.ulisboa.tecnico.meic.sec.lib.ServerCallsPoolMockup;
import pt.ulisboa.tecnico.meic.sec.lib.exception.NotEnoughResponsesConsensusException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static junit.framework.TestCase.fail;

public class PwdManagerClientTwoFaultyNodeMockupTest {
    private static final String KEYSTORE_PASSWORD = "batata";
    private PwdManagerClient client;

    @Before
    public void setUp() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
        client = new PwdManagerClient();
        ServerCallsPoolMockup pool = new ServerCallsPoolMockup(2, 1, 1);

        KeyStore ks = CryptoUtilities.readKeystoreFile("keystore.jceks", KEYSTORE_PASSWORD.toCharArray());
        client.init(ks, "asymm", KEYSTORE_PASSWORD.toCharArray(), "symm", KEYSTORE_PASSWORD.toCharArray(), pool);
        client.register_user();
    }

    @After
    public void tearDown() {
    }

    @Test(expected = NotEnoughResponsesConsensusException.class)
    public void testSimpleSave() throws NotEnoughResponsesConsensusException {
        client.save_password("youtube.com", "unicornio", "arcoiris");
        client.retrieve_password("youtube.com", "unicornio");
        fail("NotEnoughResponsesConsensusException should have been thrown");
    }


    @Test(expected = NotEnoughResponsesConsensusException.class)
    public void testLoopRetrieve() throws NotEnoughResponsesConsensusException {
        client.save_password("youtube.com", "unicornio", "arcoiris");
        for (int i = 0; i < 4; i++) {
            client.retrieve_password("youtube.com", "unicornio");
        }
        fail("NotEnoughResponsesConsensusException should have been thrown");
    }

    @Test(expected = NotEnoughResponsesConsensusException.class)
    public void testSaveSamePasswordDifferentDomainAndUser() throws NotEnoughResponsesConsensusException {
        final String password = "mississippi";
        client.save_password("facebook.com", "tomsawyer", password);
        client.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

        client.retrieve_password("facebook.com", "tomsawyer");
        client.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");

        fail("NotEnoughResponsesConsensusException should have been thrown");
    }

    @Test(expected = NotEnoughResponsesConsensusException.class)
    public void testSaveSameUserAndPassword() throws NotEnoughResponsesConsensusException {
        final String password = "pokemon-master";
        client.save_password("pokedex.org", "ash", password);
        client.save_password("pokecenter.net", "ash", password);

        String pwd = client.retrieve_password("pokedex.org", "ash");
        String pwd2 = client.retrieve_password("pokecenter.net", "ash");

        fail("NotEnoughResponsesConsensusException should have been thrown");
    }

    @Test(expected = NotEnoughResponsesConsensusException.class)
    public void testSaveSameDomain() throws NotEnoughResponsesConsensusException {
        final String password = "portugal";
        client.save_password("supersecret.portugal.pt", "batatinha", password);
        client.save_password("supersecret.portugal.pt", "companhia", password);

        client.retrieve_password("supersecret.portugal.pt", "batatinha");
        client.retrieve_password("supersecret.portugal.pt", "companhia");

        fail("NotEnoughResponsesConsensusException should have been thrown");
    }
}
