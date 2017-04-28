package pt.ulisboa.tecnico.meic.sec.lib.exception;

public class NotEnoughResponsesConsensusException extends Exception {
    @Override
    public String getMessage() {
        return "There were not enough valid responses to execute a consensus!";
    }
}
