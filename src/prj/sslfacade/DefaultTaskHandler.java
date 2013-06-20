package prj.sslfacade;

import java.io.IOException;

public class DefaultTaskHandler implements ITaskHandler
{
    @Override
    public void process(ITasks tasks) throws IOException
    {
        Runnable task;
        while( (task = tasks.next()) != null)
        {
            task.run();
        }
        tasks.done();
    }
}
