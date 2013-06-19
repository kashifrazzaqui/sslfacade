package prj.sslfacade;

import java.io.IOException;

public class DefaultITaskHandler implements ITaskHandler
{
    @Override
    public void process(Tasks tasks) throws IOException
    {
        Runnable task;
        while( (task = tasks.next()) != null)
        {
            task.run();
        }
        tasks.done();
    }
}
