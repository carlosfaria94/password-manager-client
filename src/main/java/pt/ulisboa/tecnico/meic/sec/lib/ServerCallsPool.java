package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;
import java.util.ArrayList;

public class ServerCallsPool implements ServerCalls {

    private static final int INITIAL_PORT = 30000;
    private static final int FINAL_PORT = 30005;

    private SingleServerCalls[] singleServerCalls;

    public ServerCallsPool() {
        singleServerCalls = new SingleServerCalls[FINAL_PORT - INITIAL_PORT + 1];
        for(int i = 0; i < singleServerCalls.length ; i++){
            singleServerCalls[i] = new SingleServerCalls(INITIAL_PORT + i);
        }
    }

    @Override
    public User register(User user) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        User[] usersResponses = new User[singleServerCalls.length];

        for(int i = 0; i < singleServerCalls.length || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls[finalI].register(user);
                } catch (IOException | RemoteServerInvalidResponseException e) {
                    e.printStackTrace();
                }
            });
        }
        for(Thread thread : threads){
            thread.start();
        }
        for(Thread thread : threads){
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        // TODO: CARLOS: Consensus XD
        final int n = singleServerCalls.length;
        if(countNotNull(usersResponses) > (2.0 / 3.0) * n - 1.0 / 6.0){
            //if assinado
                // return
        }

        // JAJAO
        throw new RuntimeException("JAJAO");
    }

    private int countNotNull(Object[] array){
        int count = 0;
        for(Object o : array){
            if(o != null) count++;
        }
        return count;
    }

    @Override
    public Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        for(int i = 0; i < singleServerCalls.length || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    singleServerCalls[finalI].putPassword(pwd);
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
        Thread[] threads = new Thread[singleServerCalls.length];
        for(int i = 0; i < singleServerCalls.length || i < threads.length ; i++){
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    singleServerCalls[finalI].retrievePassword(pwd);
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
