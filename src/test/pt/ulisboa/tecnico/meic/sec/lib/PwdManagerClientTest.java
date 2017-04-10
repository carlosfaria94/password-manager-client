package pt.ulisboa.tecnico.meic.sec.lib;

import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersIntegrityException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;
import sun.util.resources.cldr.ka.LocaleNames_ka;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;


public class PwdManagerClientTest extends TestCase {
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
        assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testSimpleRetrieve() throws ServersIntegrityException, ServersSignatureNotValidException {
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
        assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testLoopRetrieve() throws ServersIntegrityException, ServersSignatureNotValidException {
        for (int i = 0; i < 4; i++) {
            String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
            assertEquals(pwd, "arcoiris");
        }
    }

    @Test
    public void testSaveSamePasswordDifferentDomainAndUser() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "mississippi";
        pwdManagerClient.save_password("facebook.com", "tomsawyer", password);
        pwdManagerClient.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

        String pwd = pwdManagerClient.retrieve_password("facebook.com", "tomsawyer");
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");
        assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameUserAndPassword() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "pokemon-master";
        pwdManagerClient.save_password("pokedex.org", "ash", password);
        pwdManagerClient.save_password("pokecenter.net", "ash", password);

        String pwd = pwdManagerClient.retrieve_password("pokedex.org", "ash");
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("pokecenter.net", "ash");
        assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameDomain() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "portugal";
        pwdManagerClient.save_password("supersecret.portugal.pt", "batatinha", password);
        pwdManagerClient.save_password("supersecret.portugal.pt", "companhia", password);

        String pwd = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "batatinha");
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "companhia");
        assertEquals(pwd2, password);
    }

    @Test
    public void testUpdatePassword() throws ServersIntegrityException, ServersSignatureNotValidException {
        final String password = "sec";
        pwdManagerClient.save_password("youtube.com", "ist", password);
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "ist");
        assertEquals(pwd, password);
        pwdManagerClient.save_password("youtube.com", "ist", password + "123");
        String pwd2 = pwdManagerClient.retrieve_password("youtube.com", "ist");
        assertEquals(pwd2, password + "123");
    }

    @Test
    public void testSortLocalPasswords(){
        LocalPassword[] l = new LocalPassword[2];
        LocalPassword test = new LocalPassword("123", "123", "0000", "2");
        l[0] = new LocalPassword("123", "123", "133", "1");
        l[1] = test;
        Arrays.sort(l);
        assertEquals(l[0], test);
    }
}