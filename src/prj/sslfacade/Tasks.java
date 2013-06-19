package prj.sslfacade;

import java.io.IOException;

public class Tasks
{
    private final Worker _worker;
    private final Handshaker _hs;

    public Tasks(Worker worker, Handshaker hs)
    {
        _worker = worker;
        _hs = hs;
    }

    public Runnable next()
    {
        return _worker.getDelegatedTask();
    }

    public void done() throws IOException
    {
        _hs.carryOn();
    }
}
