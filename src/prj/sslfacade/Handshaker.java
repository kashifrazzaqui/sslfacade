package prj.sslfacade;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus;

public class Handshaker
{
    /*
         The purpose of this class is to conduct a SSL handshake. To do this it
         requires a SSLEngine as a provider of SSL knowhow. Byte buffers that are
         required by the SSLEngine to execute its wrap and unwrap methods. And a
         TaskHandler callback that is used to delegate the responsibility of
         executing long-running/IO tasks to the host application. By providing a
         TaskHandler the host application gains the flexibility of executing
         these tasks in compliance with its own compute/IO strategies.
         */

    private final TaskHandler _taskHandler;
    private final Worker _worker;
    private boolean _finished;
    private HandshakeCompletedListener _hscl;

    public Handshaker(Worker worker, TaskHandler taskHandler)
    {
        _worker = worker;
        _taskHandler = taskHandler;
        _finished = false;
        _hscl = null;
    }

    public void begin() throws IOException, InsufficentUnwrapData
    {
        _worker.beginHandshake();
        shakehands(getHandshakeStatus());
    }

    public void carryOn(ByteBuffer data) throws IOException, InsufficentUnwrapData
    {
        //data can be null when resuming from a previous NEED_TASK state
        if (data != null)
        {
            _worker.loadUnwrapPayload(data);
        }
        shakehands(getHandshakeStatus());
    }

    public void addCompletedListener(HandshakeCompletedListener hscl)
    {
        _hscl = hscl;
    }

    public void removeCompletedListener(HandshakeCompletedListener hscl)
    {
        _hscl = hscl;
    }

    public boolean isFinished()
    {
        return _finished;
    }


    /* Privates */
    private void shakehands(HandshakeStatus handshakeStatus) throws IOException, InsufficentUnwrapData
    {
        switch (handshakeStatus)
        {
            case NOT_HANDSHAKING:
                break;
            case FINISHED:
                handshakeFinished();
                break;
            case NEED_TASK:
                _taskHandler.process(new Tasks(_worker));
                break;
            case NEED_WRAP:
                SSLEngineResult w_result = _worker.doWrap();
                if (isSuccessful(w_result))
                {
                    _worker.emitWrappedData(w_result);
                }
                else
                {
                    processSSLEngineResult(w_result, handshakeStatus);
                }
                break;
            case NEED_UNWRAP:
                SSLEngineResult u_result = _worker.doUnwrap();
                processSSLEngineResult(u_result, handshakeStatus);
                break;
        }
    }

    private boolean isSuccessful(SSLEngineResult w_result)
    {
        return w_result.getStatus().equals(SSLEngineResult.Status.OK);
    }

    private void handshakeFinished()
    {
        _finished = true;
        _hscl.onComplete();
    }

    private HandshakeStatus getHandshakeStatus()
    {
        return _worker.getHandshakeStatus();
    }

    private void processSSLEngineResult(SSLEngineResult result, SSLEngineResult.HandshakeStatus hs) throws IOException, InsufficentUnwrapData
    {
        switch (result.getStatus())
        {
            case BUFFER_UNDERFLOW:
                if (wrapping(hs))
                {
                    /*
                     Should never occur because for outgoing data OUT_PLAIN
                     is the source buffer which is used during a wrap. There
                     is no limitation on how little data can be  wrapped/encrypted.

                     It may be possible for this to occur because of a
                     programmer error. The programmer could have called wrap
                     on an empty source buffer. In such a case throwing an
                     RuntimeException is best because there should be no
                     condition in which such a use case should legitimately
                     occur.

                     At the time of writing this it is not clear if any other
                     situations exist where this case is possible.
                     Unfortunately no documentation exists on this subject.
                     */
                    throw new RuntimeException("ERROR: Buffer underflow in a wrap!");
                }
                else /* unwrap */
                {
                    /*
                     While unwrapping if the source cipher data is
                     insufficient.

                     This can occur because the host
                     application has not provided enough data. The host
                     application should wait for more data and then retry ALL
                     unprocessed data again.

                     This cannot occur because there is insufficent space in the
                     IN_CIPHER(source) buffer because when the host application
                     attempts to write into IN_CIPHER then it get a
                     BufferOverflowException. In such a case,
                     the host application can call the resetSize method on
                     Buffers and specify a sufficient size and then retry ALL
                     data again.
                     */

                    //TODO: Store insufficient unwrap data
                    throw new InsufficentUnwrapData(
                            "Need more cipher data to unwrap.");
                }
            case BUFFER_OVERFLOW:
                if (wrapping(hs))
                {
                    _worker.handleBufferOverflow(BufferType.OUT_PLAIN,
                            BufferType.OUT_CIPHER);
                }
                else
                {
                    _worker.handleBufferOverflow(BufferType.IN_CIPHER,
                            BufferType.IN_PLAIN);
                }
                shakehands(getHandshakeStatus());
                break;
            case CLOSED:
                //TODO - its all over but should we mark handshake finished?
                break;
        }
    }

    private boolean wrapping(SSLEngineResult.HandshakeStatus hs)
    {
        return hs.equals(SSLEngineResult.HandshakeStatus.NEED_WRAP);
    }
}
