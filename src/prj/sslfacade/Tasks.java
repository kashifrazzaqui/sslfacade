package prj.sslfacade;

public class Tasks
{
    private final Worker _worker;

    public Tasks(Worker worker)
    {
        _worker = worker;
    }

    public Runnable next()
    {
        return _worker.getDelegatedTask();
    }
}
