package pt.ulisboa.tecnico.meic.sec.lib;

import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;

public interface ServerCalls {
    User register(User user) throws IOException, RemoteServerInvalidResponseException;

    Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException;

    Password retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException;
}
