package prj.sslfacade;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

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

    void begin() throws SSLException
    {
        _worker.beginHandshake();
        shakehands();
    }

    void carryOn() throws SSLException
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
    private void shakehands() throws SSLException
    {
        System.out.println("HS: " + _worker.getHandshakeStatus());
        switch (_worker.getHandshakeStatus())
        {
            case NOT_HANDSHAKING:
                /* Occurs after handshake is over */
                break;
            case FINISHED:
                handshakeFinished();
                break;
            case NEED_TASK:
                _taskHandler.process(new Tasks(_worker, this));
                break;
            case NEED_WRAP:
                SSLEngineResult w_result = _worker.wrap(null);
                System.out.println("DBG: " + w_result);
                if (w_result.getHandshakeStatus().equals(SSLEngineResult
                        .HandshakeStatus.FINISHED))
                {
                    handshakeFinished();
                }
                else
                {
                    shakehands();
                }
                break;
            case NEED_UNWRAP:
                System.out.println("Shakehands.NEED_UNWRAP: " + _worker.pendingUnwrap());
                if (_worker.pendingUnwrap())
                {
                    SSLEngineResult u_result = _worker.unwrap(null);
                    if (u_result.getStatus().equals(SSLEngineResult.Status.OK))
                    {
                        shakehands();
                    }
                }
                break;
        }
    }

    private void handshakeFinished()
    {
        _finished = true;
        _hscl.onComplete();
    }

}
