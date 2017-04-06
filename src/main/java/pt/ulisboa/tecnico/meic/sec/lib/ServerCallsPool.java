package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.CryptoManager;
import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;
import pt.ulisboa.tecnico.meic.sec.lib.exception.ServersSignatureNotValidException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;


public class ServerCallsPool implements ServerCalls {

    private int initialPort = 30000;
    private int finalPort = 30005;

    private SingleServerCalls[] singleServerCalls;
    private PwdManagerClient pwdManagerClient;

    public ServerCallsPool(int initialPort, int finalPort, PwdManagerClient pwdManagerClient) {
        this.initialPort = initialPort;
        this.finalPort = finalPort;
        this.pwdManagerClient = pwdManagerClient;
        init();
    }

    public ServerCallsPool(PwdManagerClient pwdManagerClient) {
        this.pwdManagerClient = pwdManagerClient;
        init();
    }

    private void init() {
        singleServerCalls = new SingleServerCalls[finalPort - initialPort + 1];
        for(int i = 0; i < singleServerCalls.length ; i++){
            singleServerCalls[i] = new SingleServerCalls(initialPort + i);
        }
    }

    @Override
    public User register(User user) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        User[] usersResponses = new User[singleServerCalls.length];

        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    usersResponses[finalI] = singleServerCalls[finalI].register(user);
                } catch (IOException | RemoteServerInvalidResponseException e) {
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

        final int n = singleServerCalls.length;
        /* If there were more responses than the number of faults we tolerate, than we will proceed
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        if(countNotNull(usersResponses) > (2.0 / 3.0) * n - 1.0 / 6.0){
            //if assinado
            // return
            //PublicKey publicKey = CryptoUtilities.getPublicKeyFromKeystore(keyStore, asymAlias, asymPwd);
            List<User> failResponses = new ArrayList<>();
            List<User> goodResponses = new ArrayList<>();
            for (User userRes : usersResponses) {
                if (userRes == null) {
                    failResponses.add(userRes);
                /*} else if (cryptoManager.isValidSig(publicKey, new String[]{user.getFingerprint()}, userRes.getFingerprint()) {
                    // Validar o fingerprint devolvido se é um digest da publicKey do client
                    goodResponses.add(userRes);
                } else {
                    failResponses.add(userRes);*/
                }
            }

            /*
             * If we obtain more good responses than fail/bad responses, means that the system is ok, otherwise, we cannot
             * rely on the system
             */
            if (goodResponses.size() > failResponses.size() && goodResponses.size() > (2.0 / 3.0) * n - 1.0 / 6.0) {
                return goodResponses.get(0);
            } else {
                // JAJAO
                throw new RuntimeException("JAJAO");
            }

        } else {
            // JAJAO
            throw new RuntimeException("JAJAO");
        }


    }

    private int countNotNull(Object[] array) {
        int count = 0;
        for (Object o : array) {
            if (o != null) count++;
        }
        return count;
    }

    @Override
    public Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    singleServerCalls[finalI].putPassword(pwd);
                } catch (IOException | RemoteServerInvalidResponseException e) {
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
        return null;
    }

    @Override
    public Password retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        Thread[] threads = new Thread[singleServerCalls.length];
        Password[] passwordsResponse = new Password[singleServerCalls.length];
        for (int i = 0; i < singleServerCalls.length || i < threads.length; i++) {
            int finalI = i;
            threads[i] = new Thread(() -> {
                try {
                    passwordsResponse[finalI] = singleServerCalls[finalI].retrievePassword(pwd);
                } catch (IOException | RemoteServerInvalidResponseException e) {
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

        for (int i = 0; i < passwordsResponse.length; i++) {
            Password p = passwordsResponse[i];
            if (p != null) {
                try {
                    pwdManagerClient.verifyServersSignature(p);
                } catch (InvalidKeySpecException | NoSuchAlgorithmException | SignatureException | InvalidKeyException | ServersSignatureNotValidException e) {
                    passwordsResponse[i] = null;
                }
            }
        }

        final int n = singleServerCalls.length;
        /* If there were more responses than the number of faults we tolerate, than we will proceed
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        if(countNotNull(passwordsResponse) > (2.0 / 3.0) * n - 1.0 / 6.0) {



        }
        return null;
    }
}
