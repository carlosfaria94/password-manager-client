package pt.ulisboa.tecnico.meic.sec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.lib.LocalPassword;
import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;
import pt.ulisboa.tecnico.meic.sec.lib.exception.AllNullException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.NotEnoughResponsesConsensusException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.UUID;

import static junit.framework.TestCase.fail;

public class PwdManagerClientTest {
    static final String KEYSTORE_PASSWORD = "batata";

    PwdManagerClient client;

    @Before
    public void setUp() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
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
    public void testSimpleSave()  {
        try {
            client.save_password("youtube.com", "unicornio", "arcoiris");
            LocalPassword  pwd = client.retrieve_password("youtube.com", "unicornio");
            Assert.assertEquals(pwd.getPassword(), "arcoiris");
        } catch (AllNullException | NotEnoughResponsesConsensusException e) {
            e.printStackTrace();
            fail("NotEnoughResponsesConsensusException should have not be thrown");
        }
    }

    @Test
    public void testLoopRetrieve()  {
        try {
            client.save_password("youtube.com", "unicornio", "arcoiris");
            for (int i = 0; i < 4; i++) {
                LocalPassword  pwd = client.retrieve_password("youtube.com", "unicornio");
                Assert.assertEquals(pwd.getPassword(), "arcoiris");
            }
        } catch (AllNullException | NotEnoughResponsesConsensusException e) {
            e.printStackTrace();
            fail("NotEnoughResponsesConsensusException should have not been thrown");
        }
    }

    @Test
    public void testSaveSamePasswordDifferentDomainAndUser()  {
        try {
            final String password = "mississippi";
            client.save_password("facebook.com", "tomsawyer", password);
            client.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

            LocalPassword  pwd = client.retrieve_password("facebook.com", "tomsawyer");
            Assert.assertEquals(pwd.getPassword(), password);
            LocalPassword  pwd2 = client.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");
            Assert.assertEquals(pwd2.getPassword(), password);
        } catch (AllNullException | NotEnoughResponsesConsensusException e) {
            e.printStackTrace();
            fail("NotEnoughResponsesConsensusException should have not been thrown");
        }
    }

    @Test
    public void testSaveSameUserAndPassword()  {
        try {
            final String password = "pokemon-master";
            client.save_password("pokedex.org", "ash", password);
            client.save_password("pokecenter.net", "ash", password);

            LocalPassword  pwd = client.retrieve_password("pokedex.org", "ash");
            Assert.assertEquals(pwd.getPassword(), password);
            LocalPassword  pwd2 = client.retrieve_password("pokecenter.net", "ash");
            Assert.assertEquals(pwd2.getPassword(), password);
        } catch (AllNullException | NotEnoughResponsesConsensusException e) {
            e.printStackTrace();
            fail("NotEnoughResponsesConsensusException should have not been thrown");
        }
    }

    @Test
    public void testSaveSameDomain()  {
        try {
            final String password = "portugal";
            client.save_password("supersecret.portugal.pt", "batatinha", password);
            client.save_password("supersecret.portugal.pt", "companhia", password);

            LocalPassword pwd = client.retrieve_password("supersecret.portugal.pt", "batatinha");
            Assert.assertEquals(pwd.getPassword(), password);
            LocalPassword  pwd2 = client.retrieve_password("supersecret.portugal.pt", "companhia");
            Assert.assertEquals(pwd2.getPassword(), password);
        } catch (AllNullException | NotEnoughResponsesConsensusException e) {
            e.printStackTrace();
            fail("NotEnoughResponsesConsensusException should have not been thrown");
        }
    }

    @Test
    public void testSortLocalPasswords() {
        LocalPassword[] l = new LocalPassword[2];
        LocalPassword test = new LocalPassword("123", "123", "0000",
                "2", UUID.nameUUIDFromBytes("ola".getBytes()).toString());
        l[0] = new LocalPassword("123", "123", "133", "1",
                UUID.nameUUIDFromBytes("adeus".getBytes()).toString());
        l[1] = test;
        /*for(LocalPassword ll : l){
            System.out.println(ll);
        }*/
        Arrays.sort(l);
        Assert.assertEquals(l[0], test);
    }
}
