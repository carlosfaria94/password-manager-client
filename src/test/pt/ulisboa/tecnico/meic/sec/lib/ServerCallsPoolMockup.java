package pt.ulisboa.tecnico.meic.sec.lib;

import java.security.NoSuchAlgorithmException;

public class ServerCallsPoolMockup extends ServerCallsPool {
    public ServerCallsPoolMockup(int goodNodes) throws NoSuchAlgorithmException {
        this(goodNodes, 0, 0);
    }

    public ServerCallsPoolMockup(int goodNodes, int faultyNullNodes) throws NoSuchAlgorithmException {
        this(goodNodes, faultyNullNodes, 0);
    }

    public ServerCallsPoolMockup(int goodNodes, int faultyNullNodes, int faultyIntegrityNodes)
            throws NoSuchAlgorithmException {
        SingleServerCallsMockup[] pool =
                new SingleServerCallsMockup[goodNodes + faultyNullNodes + faultyIntegrityNodes];

        for (int i = 0; i < goodNodes; i++)
            pool[i] = new SingleServerCallsMockup();

        for (int i = 0; i < faultyNullNodes; i++)
            pool[goodNodes + i] = new SingleServerCallsFaultyNullMockup();

        for (int i = 0; i < faultyIntegrityNodes; i++)
            pool[goodNodes + faultyNullNodes + i] = new SingleServerCallsFaultyIntegrityMockup();

        setSingleServerCalls(pool);
        setNodes();
    }

    public void setNodes(){
        for(SingleServerCalls s: getSingleServerCalls()){
            SingleServerCallsMockup server = (SingleServerCallsMockup) s;
            server.addNodes(this);
        }
    }
}
