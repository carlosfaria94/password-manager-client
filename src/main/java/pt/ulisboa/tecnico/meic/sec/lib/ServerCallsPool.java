package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;
import java.util.ArrayList;

public class ServerCallsPool implements ServerCalls {

    private static final int INITIAL_PORT = 30000;
    private static final int FINAL_PORT = 30005;

    private ArrayList<ServerCalls> listCalls;

    public ServerCallsPool() {
        listCalls = new ArrayList<>();
        for(int i = INITIAL_PORT; i < FINAL_PORT ; i++){
            listCalls.add(new SingleServerCalls(i));
        }
    }

    @Override
    public User register(User user) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[listCalls.size()];
        for(int i = 0 ; i < listCalls.size() || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    listCalls.get(finalI).register(user);
                } catch (IOException | RemoteServerInvalidResponseException e) {
                    e.printStackTrace();
                }
            });
        }
        for(Thread thread : threads){
            thread.start();
        }

        // Some consensus code here

        for(Thread thread : threads){
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[listCalls.size()];
        for(int i = 0 ; i < listCalls.size() || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    listCalls.get(finalI).putPassword(pwd);
                } catch (IOException | RemoteServerInvalidResponseException e) {
                    e.printStackTrace();
                }
            });
        }
        for(Thread thread : threads){
            thread.start();
        }

        // Some consensus code here

        for(Thread thread : threads){
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public Password retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[listCalls.size()];
        for(int i = 0 ; i < listCalls.size() || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    listCalls.get(finalI).retrievePassword(pwd);
                } catch (IOException | RemoteServerInvalidResponseException e) {
                    e.printStackTrace();
                }
            });
        }
        for(Thread thread : threads){
            thread.start();
        }

        // Some consensus code here

        for(Thread thread : threads){
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
}
