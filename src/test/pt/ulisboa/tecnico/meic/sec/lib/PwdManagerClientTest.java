package pt.ulisboa.tecnico.meic.sec.lib;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;


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
    public void testSimpleSave() {
        pwdManagerClient.save_password("youtube.com", "unicornio", "arcoiris");
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
        System.out.println(pwd);
        assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testSimpleRetrieve() {
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
        System.out.println(pwd);
        assertEquals(pwd, "arcoiris");
    }

    @Test
    public void testLoopRetrieve() {
        for(int i = 0 ; i < 4 ; i++) {
            String pwd = pwdManagerClient.retrieve_password("youtube.com", "unicornio");
            System.out.println(pwd);
            assertEquals(pwd, "arcoiris");
        }
    }

    @Test
    public void testSaveSamePasswordDifferentDomainAndUser() {
        final String password = "mississippi";
        pwdManagerClient.save_password("facebook.com", "tomsawyer", password);
        pwdManagerClient.save_password("fenix.ist.utl.pt", "huckleberry_finn", password);

        String pwd = pwdManagerClient.retrieve_password("facebook.com", "tomsawyer");
        System.out.println(pwd);
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("fenix.ist.utl.pt", "huckleberry_finn");
        System.out.println(pwd2);
        assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameUserAndPassword() {
        final String password = "pokemon-master";
        pwdManagerClient.save_password("pokedex.org", "ash", password);
        pwdManagerClient.save_password("pokecenter.net", "ash", password);

        String pwd = pwdManagerClient.retrieve_password("pokedex.org", "ash");
        System.out.println(pwd);
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("pokecenter.net", "ash");
        System.out.println(pwd2);
        assertEquals(pwd2, password);
    }

    @Test
    public void testSaveSameDomain() {
        final String password = "portugal";
        pwdManagerClient.save_password("supersecret.portugal.pt", "batatinha", password);
        pwdManagerClient.save_password("supersecret.portugal.pt", "companhia", password);

        String pwd = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "batatinha");
        System.out.println(pwd);
        assertEquals(pwd, password);
        String pwd2 = pwdManagerClient.retrieve_password("supersecret.portugal.pt", "companhia");
        System.out.println(pwd2);
        assertEquals(pwd2, password);
    }

    @Test
    public void testUpdatePassword() {
        final String password = "sec";
        pwdManagerClient.save_password("youtube.com", "ist", password);
        String pwd = pwdManagerClient.retrieve_password("youtube.com", "ist");
        System.out.println(pwd);
        assertEquals(pwd, password);
        pwdManagerClient.save_password("youtube.com", "ist", password + "123");
        String pwd2 = pwdManagerClient.retrieve_password("youtube.com", "ist");
        System.out.println(pwd2);
        assertEquals(pwd2, password + "123");
    }


    @Test
    public void doNothing(){
        // Just to run setUp and tearDown
    }
}