package prj.sslfacade;

public interface TaskHandler
{
    /*
    In order to continue handshakes after tasks are processed the
    Handshaker.carryOn method must be called.
     */
    public void process(Tasks tasks);
}
