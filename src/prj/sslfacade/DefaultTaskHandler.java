package prj.sslfacade;

import javax.net.ssl.SSLException;

public class DefaultTaskHandler implements ITaskHandler
{
    @Override
    public void process(ITasks tasks) throws SSLException
    {
        Runnable task;
        while( (task = tasks.next()) != null)
        {
            task.run();
        }
        tasks.done();
    }
}
