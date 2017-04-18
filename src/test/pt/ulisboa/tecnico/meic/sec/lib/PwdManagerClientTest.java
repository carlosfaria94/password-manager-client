package pt.ulisboa.tecnico.meic.sec.lib;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.UUID;


public class PwdManagerClientTest {
    private static final String BATATA = "batata";
    private PwdManagerClient pwdManagerClient;

    @Before
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        pwdManagerClient = new PwdManagerClient();

        KeyStore ks = CryptoUtilities.readKeystoreFile("keystore.jceks", BATATA.toCharArray());
        pwdManagerClient.init(ks, "asymm", BATATA.toCharArray(), "symm", BATATA.toCharArray());
        pwdManagerClient.register_user();
    }

    @After
    public void tearDown() {
        pwdManagerClient.close();
    }

    @Test
    public void testSimpleSave() throws ServersIntegrityException, ServersSignatureNotValidException {
        pwdManagerClient.save_password("youtube.com", "unicornio", "arcoiris");
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
        Assert.assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testSimpleRetrieve() throws ServersIntegrityException, ServersSignatureNotValidException {
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
        Assert.assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testLoopRetrieve() throws ServersIntegrityException, ServersSignatureNotValidException {
        for (int i = 0; i < 4; i++) {
            String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
            Assert.assertEquals(pwd, "arcoiris");
        }
    }

    @Test
    public void testSaveSamePasswordDifferentDomainAndUser() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "mississippi";
        pwdManagerClient.save_password("facebook.com", "tomsawyer", password);
        pwdManagerClient.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

        String pwd = pwdManagerClient.retrieve_password("facebook.com", "tomsawyer");
        Assert.assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");
        Assert.assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameUserAndPassword() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "pokemon-master";
        pwdManagerClient.save_password("pokedex.org", "ash", password);
        pwdManagerClient.save_password("pokecenter.net", "ash", password);

        String pwd = pwdManagerClient.retrieve_password("pokedex.org", "ash");
        Assert.assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("pokecenter.net", "ash");
        Assert.assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameDomain() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "portugal";
        pwdManagerClient.save_password("supersecret.portugal.pt", "batatinha", password);
        pwdManagerClient.save_password("supersecret.portugal.pt", "companhia", password);

        String pwd = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "batatinha");
        Assert.assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "companhia");
        Assert.assertEquals(pwd2, password);
    }

    @Test
    public void testUpdatePassword() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "sec";
        pwdManagerClient.save_password("youtube.com", "ist", password);
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "ist");
        Assert.assertEquals(pwd, password);
        pwdManagerClient.save_password("youtube.com", "ist", password + "123");
        String pwd2 = pwdManagerClient.retrieve_password("youtube.com", "ist");
        Assert.assertEquals(pwd2, password + "123");
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