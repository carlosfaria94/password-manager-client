package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.lib.LocalPassword;
import pt.ulisboa.tecnico.meic.sec.lib.PwdManagerClient;

import java.lang.reflect.Array;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Application {
    private static final String PASSWORD = "batata";

    public static void main(String[] args) {
        String ksPath;
        if (args.length != 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s keystorePath%n", Application.class.getName());
            System.err.println("Assuming default path.");
            ksPath = "keystore.jceks";
        } else
            ksPath = args[0];

        try {

            PwdManagerClient client = new PwdManagerClient();

            final KeyStore keyStore = CryptoUtilities.readKeystoreFile(ksPath, PASSWORD.toCharArray());
            client.init(keyStore, "asymm", PASSWORD.toCharArray(), "symm", PASSWORD.toCharArray());

            Scanner scanner = new Scanner(System.in);
            while (true) {
                try {
                    System.out.print("\n\nMenu\n" +
                            "0 - Exit\n" +
                            "1 - Register\n" +
                            "2 - Save Password\n" +
                            "3 - Retrieve Password\n" +
                            "4 - Hello\n" +
                            "\n> ");
                    int option;
                    try {
                        option = scanner.nextInt();
                    } catch (InputMismatchException e) {
                        scanner.nextLine();
                        System.err.println("Not a number.");
                        continue;
                    }
                    scanner.nextLine();


                    if (option == 0) {
                        System.out.println("Exiting...");
                        client.close();
                        System.exit(0);
                    }
                    switch (option) {
                        // Register
                        case 1:
                            System.out.println("Registering user...");
                            client.register_user();
                            break;
                        //Save Pwd
                        case 2:
                            System.out.println("Fill the following fields:");
                            System.out.print("Domain: ");
                            String domain = scanner.nextLine();
                            System.out.print("Username: ");
                            String username = scanner.nextLine();
                            System.out.print("Password: ");
                            String pwd = scanner.nextLine();
                            client.save_password(domain, username, pwd);
                            break;
                        // retrieve
                        case 3:
                            System.out.println("Fill the following fields:");
                            System.out.print("Domain: ");
                            String domain2 = scanner.nextLine();
                            System.out.print("Username: ");
                            String username2 = scanner.nextLine();
                            System.out.println("Password retrieved: " + client.retrieve_password(domain2, username2));
                            break;

                        case 4:
                            System.out.println(client.helloWorld());
                            break;

                        default:
                            System.out.println("No puedo!");
                            break;
                    }
                } catch (Exception e1) {
                    e1.printStackTrace();

                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
