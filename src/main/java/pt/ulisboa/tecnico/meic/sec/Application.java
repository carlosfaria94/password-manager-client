package pt.ulisboa.tecnico.meic.sec;

import java.io.IOException;

public class Application {
    public static void main(String[] args){
        PwdManagerClient client = new PwdManagerClient();
        System.out.println(client.helloWorld());

        ServerCalls call = new ServerCalls();
        try {
            System.out.println(call.run("http://carlosfaria.com"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
