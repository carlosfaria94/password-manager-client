package pt.ulisboa.tecnico.meic.sec.lib.exception;

public class AllNullException extends Exception {
    @Override
    public String getMessage() {
        return "Everything null!";
    }
}
