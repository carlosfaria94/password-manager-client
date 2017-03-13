package pt.ulisboa.tecnico.meic.sec.lib.exception;

/**
 * Created by francisco on 13/03/2017.
 */
public class ServersSignatureNotValidException extends RuntimeException
{
    @Override
    public String getMessage() {
        return "Server's Signature is not valid.\nPossible man-in-the-middle attack attempt!";
    }
}
