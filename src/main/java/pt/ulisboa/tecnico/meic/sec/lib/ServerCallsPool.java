package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.NotEnoughResponsesConsensusException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;

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

    public Password putPassword(Password pwd) throws IOException, NotEnoughResponsesConsensusException {
        final Password[] response = new Password[1];
        ArrayList<Integer> replicasAlreadyVisited = new ArrayList<>();
        // 0 - if for some reason replica returned null we try another one
        // 1 - if we reached every replica we stop
        final boolean[] state = {false, false};
        do {
            Thread thread = new Thread(() -> {
                try {
                    int replica, counter = 0;
                    do {
                        replica = new Random().nextInt(size());
                        if (++counter == size()) { // If we tried all replicas
                            state[1] = true;
                            return;
                        }
                    } while (replicasAlreadyVisited.contains(replica));

                    replicasAlreadyVisited.add(replica);
                    response[0] = singleServerCalls[replica].putPassword(pwd);
                } catch (Exception ignored) {
                } finally {
                    if (response[0] == null) {
                        state[0] = true;
                    }
                }
            });
            thread.start();
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            if (state[1]) {
                // There is no more replicas
                throw new NotEnoughResponsesConsensusException();
            }
        } while (state[0]);

        return response[0];
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


    //Mockup purpose
    public SingleServerCalls[] getSingleServerCalls() {
        return singleServerCalls;
    }
}
