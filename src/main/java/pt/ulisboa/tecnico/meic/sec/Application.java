package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;

import java.io.Console;
import java.security.KeyStore;
import java.util.Scanner;

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
        char[] password = console.readPassword(); // batata

        try {
            KeyStore ks = CryptoUtilities.readKeystoreFile(args[0], password);
            Scanner scanner = new Scanner(System.in);
            System.out.println("Asymmetric Key Alias:");
            String asymmAlias = scanner.nextLine();
            System.out.println("Asymmetric Key Password:");
            char[] asymmPassword = console.readPassword(); // batata
            System.out.println("Symmetric Key Alias:");
            String symmAlias = scanner.nextLine();
            System.out.println("Symmetric Key Password:");
            char[] symmPassword = console.readPassword(); // batata

            client.init(ks, asymmAlias, asymmPassword, symmAlias, symmPassword);
            client.register_user();
            client.save_password("youtube.com", "batata", "batata123");
            System.out.println(client.retrieve_password("youtube.com", "batata"));
            client.save_password("youtube.com", "batata", "batata123");
            System.out.println(client.retrieve_password("youtube.com", "batata"));
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
            System.exit(0);
        }
    }
}
