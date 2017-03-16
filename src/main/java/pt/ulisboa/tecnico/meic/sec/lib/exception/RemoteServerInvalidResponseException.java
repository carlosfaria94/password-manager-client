package pt.ulisboa.tecnico.meic.sec.lib.exception;

/**
 * Created by Bernardo on 15/03/2017.
 */
public class RemoteServerInvalidResponseException extends Exception{
    @Override
    public String getMessage() {
        return "Invalid request sent to server";
    }
}
