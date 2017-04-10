package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;


public class ServerCallsPool {

    private int initialPort = 3001;
    private int finalPort = 3004;

    private SingleServerCalls[] singleServerCalls;

    public ServerCallsPool(int initialPort, int finalPort) {
        this.initialPort = initialPort;
        this.finalPort = finalPort;
        init();
    }

    public ServerCallsPool() {
        init();
    }

    public int size() {
        return singleServerCalls.length;
    }

    private void init() {
        singleServerCalls = new SingleServerCalls[finalPort - initialPort + 1];
        for (int i = 0; i < singleServerCalls.length; i++) {
            singleServerCalls[i] = new SingleServerCalls(initialPort + i);
        }
    }

    public User[] register(User user) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        User[] usersResponses = new User[singleServerCalls.length];

        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls[finalI].register(user);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return usersResponses;
    }


    public Password[] putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].putPassword(pwd);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }

        // Some consensus code here

        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return passwordsResponse;
    }

    public Password[] retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].retrievePassword(pwd);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return passwordsResponse;
    }
}
