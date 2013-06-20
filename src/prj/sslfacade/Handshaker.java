package prj.sslfacade;

import java.io.IOException;

class Handshaker
{
    /*
         The purpose of this class is to conduct a SSL handshake. To do this it
         requires a SSLEngine as a provider of SSL knowhow. Byte buffers that are
         required by the SSLEngine to execute its wrap and unwrap methods. And a
         ITaskHandler callback that is used to delegate the responsibility of
         executing long-running/IO tasks to the host application. By providing a
         ITaskHandler the host application gains the flexibility of executing
         these tasks in compliance with its own compute/IO strategies.
         */

    private final ITaskHandler _taskHandler;
    private final Worker _worker;
    private boolean _finished;
    private IHandshakeCompletedListener _hscl;

    public Handshaker(Worker worker, ITaskHandler taskHandler)
    {
        _worker = worker;
        _taskHandler = taskHandler;
        _finished = false;
    }

    void begin() throws IOException
    {
        _worker.beginHandshake();
        shakehands();
    }

    void carryOn() throws IOException
    {
        shakehands();
    }

    void addCompletedListener(IHandshakeCompletedListener hscl)
    {
        _hscl = hscl;
    }

    void removeCompletedListener(IHandshakeCompletedListener hscl)
    {
        _hscl = hscl;
    }

    boolean isFinished()
    {
        return _finished;
    }


    /* Privates */
    private void shakehands() throws IOException
    {
        switch (_worker.getHandshakeStatus())
        {
            case NOT_HANDSHAKING:
                System.out.println("Not handshaking!");
                //TODO: Log this
                break;
            case FINISHED:
                handshakeFinished();
                break;
            case NEED_TASK:
                _taskHandler.process(new Tasks(_worker, this));
                break;
            case NEED_WRAP:
                _worker.wrap(null);
                shakehands();
                break;
            case NEED_UNWRAP:
                break;
        }
    }

    private void handshakeFinished()
    {
        _finished = true;
        _hscl.onComplete();
    }

}
