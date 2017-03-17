package pt.ulisboa.tecnico.meic.sec.lib.exception;

/**
 * Created by francisco on 13/03/2017.
 */
public class ServersIntegrityException extends Exception
{
    @Override
    public String getMessage() {
        return "Content provided by the server was compromised.\nPossible integrity attack attempt!";
    }
}
