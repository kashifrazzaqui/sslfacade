package prj.sslfacade;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;

public class Worker
{
    private final SSLEngine _engine;
    private final Buffers _buffers;
    private SSLListener _sslListener;

    public Worker(SSLEngine engine, Buffers buffers)
    {
        _engine = engine;
        _buffers = buffers;
    }

    public void beginHandshake() throws SSLException
    {
        _engine.beginHandshake();
    }

    public Runnable getDelegatedTask()
    {
        return _engine.getDelegatedTask();
    }

    public SSLEngineResult wrap(ByteBuffer plainData) throws SSLException
    {
        //TODO: OOP-able?
        _buffers.prepareForWrap(plainData);
        SSLEngineResult result = doWrap();
        emitWrappedData(result);

        switch (result.getStatus())
        {
            case BUFFER_UNDERFLOW:
                throw new RuntimeException("BUFFER_UNDERFLOW while wrapping!");
            case BUFFER_OVERFLOW:
                _buffers.grow(BufferType.OUT_CIPHER);
                compact(plainData, result);
                wrap(plainData);
                break;
            case OK:
                break;
            case CLOSED:
                //TODO
                break;
        }
        return result;
    }

    public SSLEngineResult unwrap(ByteBuffer encryptedData) throws SSLException
    {
        //TODO: OOP-able?
        encryptedData = _buffers.prependCached(encryptedData);
        _buffers.prepareForUnwrap(encryptedData);
        SSLEngineResult result = doUnwrap();
        emitPlainData(result);

        switch (result.getStatus())
        {
            case BUFFER_UNDERFLOW:
                compact(encryptedData, result);
                _buffers.cache(encryptedData);
                break;
            case BUFFER_OVERFLOW:
                _buffers.grow(BufferType.IN_PLAIN);
                compact(encryptedData, result);
                unwrap(encryptedData);
                break;
            case OK:
                _buffers.clearCache();
                break;
            case CLOSED:
                //TODO
                break;
        }
        return result;
    }

    public void setSSLListener(SSLListener SSLListener)
    {
        this._sslListener = SSLListener;
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return _engine.getHandshakeStatus();
    }

    /* Private */

    private void emitWrappedData(SSLEngineResult result)
    {
        if (result.bytesProduced() > 0)
        {
            ByteBuffer internalCipherBuffer = _buffers.get(BufferType.OUT_CIPHER);
            _sslListener.onWrappedData(makeExternalBuffer(internalCipherBuffer));
        }
    }

    private void emitPlainData(SSLEngineResult result)
    {
        if (result.bytesProduced() > 0)
        {
            ByteBuffer internalPlainBuffer = _buffers.get(BufferType.IN_PLAIN);
            _sslListener.onPlainData(makeExternalBuffer(internalPlainBuffer));
        }

    }

    private SSLEngineResult doWrap() throws SSLException
    {
        ByteBuffer plainText = _buffers.get(BufferType.OUT_PLAIN);
        ByteBuffer cipherText = _buffers.get(BufferType.OUT_CIPHER);
        return _engine.wrap(plainText, cipherText);
    }

    private SSLEngineResult doUnwrap() throws SSLException
    {
        ByteBuffer cipherText = _buffers.get(BufferType.IN_CIPHER);
        ByteBuffer plainText = _buffers.get(BufferType.IN_PLAIN);
        return _engine.unwrap(cipherText, plainText);
    }


    private ByteBuffer makeExternalBuffer(ByteBuffer internalBuffer)
    {
        ByteBuffer newBuffer = ByteBuffer.allocate(internalBuffer.limit());
        _buffers.copy(internalBuffer, newBuffer);
        return newBuffer;
    }

    private void compact(ByteBuffer data, SSLEngineResult result)
    {
        data.position(result.bytesConsumed());
        data.compact();
    }


}
