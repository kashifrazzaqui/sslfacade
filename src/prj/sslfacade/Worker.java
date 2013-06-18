package prj.sslfacade;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class Worker
{
    private final SSLEngine _engine;
    private final Buffers _buffers;
    private final AppendableBuffer _pendingUnwrapData;
    private SSLListener _sslListener;

    public Worker(SSLEngine engine, Buffers buffers)
    {
        _engine = engine;
        _buffers = buffers;
        _pendingUnwrapData = new AppendableBuffer();
    }

    public void beginHandshake() throws SSLException
    {
        _engine.beginHandshake();
    }

    public void loadUnwrapPayload(ByteBuffer data)
    {
        _buffers.prepareForUnwrap(data);
    }

    public Runnable getDelegatedTask()
    {
        return _engine.getDelegatedTask();
    }

    public void sendCipherText(HostTransport transport) throws IOException
    {
        transport.send(_buffers.get(BufferType.OUT_CIPHER));
    }

    public void handleBufferOverflow(BufferType src, BufferType dest)
    {
        _buffers.prepareRetrial(src, dest);
        _buffers.grow(dest);
    }

    public SSLEngineResult doWrap() throws SSLException
    {
        ByteBuffer plainText = _buffers.get(BufferType.OUT_PLAIN);
        ByteBuffer cipherText = _buffers.get(BufferType.OUT_CIPHER);
        return _engine.wrap(plainText, cipherText);
    }

    public SSLEngineResult doUnwrap() throws SSLException
    {
        ByteBuffer cipherText = _buffers.get(BufferType.IN_CIPHER);
        ByteBuffer plainText = _buffers.get(BufferType.IN_PLAIN);
        return _engine.unwrap(cipherText, plainText);
    }

    public void wrap(ByteBuffer plainData) throws SSLException
    {
        //TODO: OOP-able?
        _buffers.prepareForWrap(plainData);
        SSLEngineResult result = doWrap();
        emitAnyWrappedData(result);

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
    }

    public void unwrap(ByteBuffer encryptedData) throws SSLException
    {
        //TODO: OOP-able?
        encryptedData = _pendingUnwrapData.append(encryptedData);
        _buffers.prepareForUnwrap(encryptedData);
        SSLEngineResult result = doUnwrap();
        emitAnyPlainData(result);

        switch (result.getStatus())
        {
            case BUFFER_UNDERFLOW:
                compact(encryptedData, result);
                _pendingUnwrapData.set(encryptedData);
                break;
            case BUFFER_OVERFLOW:
                _buffers.grow(BufferType.IN_PLAIN);
                compact(encryptedData, result);
                unwrap(encryptedData);
                break;
            case OK:
                _pendingUnwrapData.clear();
                break;
            case CLOSED:
                //TODO
                break;
        }
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

    private void emitAnyWrappedData(SSLEngineResult result)
    {
        if (result.bytesProduced() > 0)
        {
            ByteBuffer internalCipherBuffer = _buffers.get(BufferType.OUT_CIPHER);
            emitWrapped(makeExternalBuffer(internalCipherBuffer));
        }
    }

    private void emitAnyPlainData(SSLEngineResult result)
    {
        if (result.bytesProduced() > 0)
        {
            ByteBuffer internalPlainBuffer = _buffers.get(BufferType.IN_PLAIN);
            emitPlain(makeExternalBuffer(internalPlainBuffer));
        }

    }

    private void emitWrapped(ByteBuffer wrappedData)
    {
        _sslListener.onWrappedData(wrappedData);
    }

    private void emitPlain(ByteBuffer plainData)
    {
        _sslListener.onPlainData(plainData);
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
