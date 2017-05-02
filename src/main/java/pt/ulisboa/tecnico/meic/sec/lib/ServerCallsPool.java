package pt.ulisboa.tecnico.meic.sec.lib;

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

    public ServerCallsPool(int replicas) {
        this.finalPort = this.initialPort + replicas - 1;
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

    public User[] register(User user) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        User[] usersResponses = new User[singleServerCalls.length];

        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls[finalI].register(user);
                } catch (Exception ignored) {
                    // If a thread crashed, it's probably connection problems
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


    public Password[] putPassword(Password pwd) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].putPassword(pwd);
                } catch (Exception ignored) {
                    // If a thread crashed, it's probably connection problems
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

    public Password[] retrievePassword(Password pwd) throws IOException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].retrievePassword(pwd);
                } catch (Exception ignored) {
                    // If a thread crashed, it's probably connection problems
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

    //Mockup purpose
    public void setSingleServerCalls(SingleServerCalls[] singleServerCalls) {
        this.singleServerCalls = singleServerCalls;
    }
}
