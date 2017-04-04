package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;

/**
 * Created by francisco on 04/04/2017.
 */
public interface ServerCalls {
    User register(User user) throws IOException, RemoteServerInvalidResponseException;

    Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException;

    Password retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException;
}
