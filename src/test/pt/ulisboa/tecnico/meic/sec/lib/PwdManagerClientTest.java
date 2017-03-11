package pt.ulisboa.tecnico.meic.sec.lib;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.ulisboa.tecnico.meic.sec.CryptoUtilities;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

class PwdManagerClientTest {
    private static final String BATATA = "batata";
    private PwdManagerClient pwdManagerClient;
    private KeyStore ks;

    @BeforeEach
    void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        pwdManagerClient = new PwdManagerClient();
        ks = CryptoUtilities.readKeystoreFile("keystore.jceks", BATATA.toCharArray());
        pwdManagerClient.init(ks, "asymm", BATATA.toCharArray(), "symm", BATATA.toCharArray());
    }

    @AfterEach
    void tearDown() {
        pwdManagerClient.close();
    }

    @Test
    void test() {
        pwdManagerClient.register_user();
        pwdManagerClient.save_password("youtube.com", "unicornio", "arcoiris");
    }


}