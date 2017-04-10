package pt.ulisboa.tecnico.meic.sec.lib.exception;

/**
 * Created by francisco on 13/03/2017.
 */
public class NotEnoughResponsesConsensusException extends RuntimeException
{
    @Override
    public String getMessage() {
        return "There were not enough valid responses to execute a consensus!";
    }
}
