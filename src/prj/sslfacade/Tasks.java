package prj.sslfacade;

import javax.net.ssl.SSLEngine;

public class Tasks
{
    private final SSLEngine _engine;

    public Tasks(SSLEngine engine)
    {
       _engine = engine;
    }

    public Runnable next()
    {
        return _engine.getDelegatedTask();
    }
}
