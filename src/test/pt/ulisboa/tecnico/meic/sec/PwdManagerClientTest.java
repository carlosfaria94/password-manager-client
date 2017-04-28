package pt.ulisboa.tecnico.meic.sec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.lib.LocalPassword;
import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;
import pt.ulisboa.tecnico.meic.sec.lib.exception.NotEnoughResponsesConsensusException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.UUID;

import static junit.framework.TestCase.fail;

public class PwdManagerClientTest {
    private static final String KEYSTORE_PASSWORD = "batata";
    private static final int NUM_REPLICAS = 4;

    private PwdManagerClient client;

    @Before
    public void setUp() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, NotEnoughResponsesConsensusException {
        client = new PwdManagerClient();

        KeyStore ks = CryptoUtilities.readKeystoreFile("keystore.jceks", KEYSTORE_PASSWORD.toCharArray());
        client.init(ks, "asymm", KEYSTORE_PASSWORD.toCharArray(), "symm", KEYSTORE_PASSWORD.toCharArray());
        client.register_user();
    }

    @After
    public void tearDown() {
        client.close();
    }

    @Test
    public void testSimpleSave() {
        try {
            client.save_password("youtube.com", "unicornio", "arcoiris");
            String pwd = client.retrieve_password("youtube.com", "unicornio");
            Assert.assertEquals(pwd, "arcoiris");
        } catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testSimpleRetrieve() throws ServersSignatureNotValidException, ServersIntegrityException {
        try {
            String pwd = client.retrieve_password("youtube.com", "unicornio");
            Assert.assertEquals(pwd, "arcoiris");
        } catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testLoopRetrieve() throws ServersIntegrityException, ServersSignatureNotValidException {
        try {
            for (int i = 0; i < 4; i++) {
                String pwd = client.retrieve_password("youtube.com", "unicornio");
                Assert.assertEquals(pwd, "arcoiris");
            }
        }
        catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testSaveSamePasswordDifferentDomainAndUser() throws ServersIntegrityException, ServersSignatureNotValidException {
        try {
            final String password = "mississippi";
            client.save_password("facebook.com", "tomsawyer", password);
            client.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

            String pwd = client.retrieve_password("facebook.com", "tomsawyer");
            Assert.assertEquals(pwd, password);
            String pwd2 = client.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");
            Assert.assertEquals(pwd2, password);
        }
        catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testSaveSameUserAndPassword() throws ServersIntegrityException, ServersSignatureNotValidException {
        try {
            final String password = "pokemon-master";
            client.save_password("pokedex.org", "ash", password);
            client.save_password("pokecenter.net", "ash", password);

            String pwd = client.retrieve_password("pokedex.org", "ash");
            Assert.assertEquals(pwd, password);
            String pwd2 = client.retrieve_password("pokecenter.net", "ash");
            Assert.assertEquals(pwd2, password);
        }
        catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testSaveSameDomain() throws ServersIntegrityException, ServersSignatureNotValidException {
        try {
            final String password = "portugal";
            client.save_password("supersecret.portugal.pt", "batatinha", password);
            client.save_password("supersecret.portugal.pt", "companhia", password);

            String pwd = client.retrieve_password("supersecret.portugal.pt", "batatinha");
            Assert.assertEquals(pwd, password);
            String pwd2 = client.retrieve_password("supersecret.portugal.pt", "companhia");
            Assert.assertEquals(pwd2, password);
        }
        catch (NotEnoughResponsesConsensusException e) {
            fail("NotEnoughResponsesConsensusException should have not be thrown");
            e.printStackTrace();
        }
    }

    @Test
    public void testSortLocalPasswords(){
        LocalPassword[] l = new LocalPassword[2];
        LocalPassword test = new LocalPassword("123", "123", "0000",
                "2", UUID.nameUUIDFromBytes("ola".getBytes()).toString());
        l[0] = new LocalPassword("123", "123", "133", "1",
                UUID.nameUUIDFromBytes("adeus".getBytes()).toString());
        l[1] = test;
        for(LocalPassword ll : l){
            System.out.println(ll);
        }
        Arrays.sort(l);
        Assert.assertEquals(l[0], test);
    }
}
