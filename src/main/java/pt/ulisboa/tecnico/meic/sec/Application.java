package pt.ulisboa.tecnico.meic.sec;

import java.io.IOException;
import java.time.Instant;

public class Application {
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
    }
}
