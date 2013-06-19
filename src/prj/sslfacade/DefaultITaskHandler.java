package prj.sslfacade;

public class DefaultITaskHandler implements ITaskHandler
{
    @Override
    public void process(Tasks tasks)
    {
        Runnable task;
        while( (task = tasks.next()) != null)
        {
            task.run();
        }
        //TODO - Continue Handshake
    }
}
