package pt.ulisboa.tecnico.meic.sec.lib.exception;

/**
 * Created by francisco on 13/03/2017.
 */
public class MessageNotFreshException extends Exception {
    @Override
    public String getMessage() {
        return "Message is not fresh or already was received.\nPossible replay attack attempt!";
    }
}
