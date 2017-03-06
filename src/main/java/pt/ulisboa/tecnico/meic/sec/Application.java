package pt.ulisboa.tecnico.meic.sec;

public class Application {
    public static void main(String[] args){
        PwdManagerClient client = new PwdManagerClient();
        System.out.println(client.helloWorld());
    }
}
