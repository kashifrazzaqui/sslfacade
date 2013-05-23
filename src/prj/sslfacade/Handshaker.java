package prj.sslfacade;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus;

public class Handshaker
{
    private final SSLEngine _engine;
    private final Buffers _buffers;
    private final TaskHandler _taskHandler;
    private final Tasks _tasks;
    private boolean _finished;

    public Handshaker(SSLEngine engine, Buffers buffers, TaskHandler th)
    {
        _engine = engine;
        _taskHandler = th;
        _tasks = new Tasks(_engine);
        _buffers = buffers;
        _finished = false;
    }

    public void begin() throws SSLException
    {
        _engine.beginHandshake();
        shakehands(getHandshakeStatus());
    }

    public void carryOn() throws SSLException
    {
        shakehands(getHandshakeStatus());
    }

    private void shakehands(HandshakeStatus handshakeStatus) throws SSLException
    {
        switch (handshakeStatus)
        {
            case NOT_HANDSHAKING:
                break;
            case FINISHED:
                _finished = true;
                break;
            case NEED_TASK:
                _taskHandler.process(_tasks);
                break;
            case NEED_WRAP:
                SSLEngineResult w_result = doWrap();
                processSSLEngineResult(w_result, handshakeStatus);
                shakehands(getHandshakeStatus());
                break;
            case NEED_UNWRAP:
                SSLEngineResult u_result = doUnwrap();
                processSSLEngineResult(u_result, handshakeStatus);
                shakehands(getHandshakeStatus());
                break;
        }
    }


    private void processSSLEngineResult(SSLEngineResult result, HandshakeStatus hs)
    {
        switch (result.getStatus())
        {
            case BUFFER_UNDERFLOW:
                if (wrapping(hs))
                {
                    _buffers.manage(BufferType.OUT_PLAIN);
                }
                else
                {
                    _buffers.manage(BufferType.IN_CIPHER);
                }
                break;
            case BUFFER_OVERFLOW:
                if (wrapping(hs))
                {
                    _buffers.manage(BufferType.OUT_CIPHER);
                }
                else
                {
                    _buffers.manage(BufferType.IN_PLAIN);
                }
                break;
            case OK:
                if (wrapping(hs))
                {
                    _buffers.get(BufferType.OUT_PLAIN).clear();
                    _buffers.get(BufferType.OUT_CIPHER).flip();
                }
                else
                {
                    _buffers.get(BufferType.IN_CIPHER).clear();
                    _buffers.get(BufferType.IN_PLAIN).flip();
                }
                break;
            case CLOSED:
                //TODO - its all over but should we mark handshake finished?
                break;
        }
    }

    private boolean wrapping(HandshakeStatus hs)
    {
        return hs.equals(HandshakeStatus.NEED_WRAP);
    }


    private SSLEngineResult doWrap() throws SSLException
    {
        ByteBuffer plainText = _buffers.get(BufferType.OUT_PLAIN);
        ByteBuffer cipherText = _buffers.get(BufferType.OUT_CIPHER);
        return _engine.wrap(plainText, cipherText);
    }

    private SSLEngineResult doUnwrap() throws SSLException
    {
        ByteBuffer plainText = _buffers.get(BufferType.IN_PLAIN);
        ByteBuffer cipherText = _buffers.get(BufferType.IN_CIPHER);
        return _engine.unwrap(cipherText, plainText);
    }

    private HandshakeStatus getHandshakeStatus()
    {
        return _engine.getHandshakeStatus();
    }

    public boolean isFinished()
    {
        return _finished;
    }
}
