package pt.ulisboa.tecnico.meic.sec;

import java.io.Console;
import java.security.KeyStore;

public class Application {
    public static void main(String[] args){
        PwdManagerClient client = new PwdManagerClient();
        System.out.println(client.helloWorld());

        if(args.length != 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s keystorePath%n", Application.class.getName());
            return;
        }
        Console console = System.console();
        System.out.println("Keystore Password:");
        char[] password = console.readPassword();
        try {
            KeyStore ks = CryptoUtilities.readKeystoreFile(args[0], password);
            client.init(ks);
            client.register_user();
            client.save_password("youtube.com", "batata", "batata123");
            System.out.println(client.retrieve_password("youtube.com", "batata"));
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());

        }
    }
/*
    public static void main(String[] args){
        PwdManagerClient client = new PwdManagerClient();
        System.out.println(client.helloWorld());

        ServerCalls call = new ServerCalls();
        try {
            String publicKey = "oooo";

            User user = new User(publicKey);
            call.register(user);

            Password pwdToRegister = new Password(
                    publicKey,
                    "xxsd.com",
                    "kkkk",
                    "ups",
                    "SIGN1",
                    Instant.now(),
                    "ttt",
                    "SIGN2"
            );
            call.putPassword(pwdToRegister);

            Password pwdToRetrieve = new Password(
                    publicKey,
                    "ttt.com",
                    "carlosfaria",
                    "SIGN1",
                    Instant.now(),
                    "ttt",
                    "SIGN2"
            );
            call.retrievePassword(pwdToRetrieve);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/
}
