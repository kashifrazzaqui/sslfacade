package prj.sslfacade;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class SSLFacade implements ISSLFacade
{
    private Handshaker _handshaker;
    private HandshakeCompletedListener _hcl;
    private final Worker _worker;

    public SSLFacade(SSLContext context, boolean client,
                     boolean clientAuthRequired, ITaskHandler taskHandler)
    {
        //Currently there is no support for SSL session reuse,
        // so no need to take a peerhost or port from the host application
        SSLEngine engine = makeSSLEngine(context, client, clientAuthRequired);
        Buffers buffers = new Buffers(engine.getSession());
        _worker = new Worker(engine, buffers);
        _handshaker = new Handshaker(_worker, taskHandler);
    }

    @Override
    public void setHandshakeCompletedListener(HandshakeCompletedListener hcl)
    {
        _hcl = hcl;
    }

    @Override
    public void setSSLListener(SSLListener l)
    {
        _worker.setSSLListener(l);
    }

    @Override
    public void beginHandshake() throws IOException
    {
        attachCompletionListener();
        _handshaker.begin();
    }

    @Override
    public boolean isHandshakeCompleted()
    {
        return _handshaker == null || _handshaker.isFinished();
    }

    @Override
    public void encrypt(ByteBuffer plainData) throws SSLException
    {
        _worker.wrap(plainData);
    }


    @Override
    public void decrypt(ByteBuffer encryptedData) throws IOException
    {
        _worker.unwrap(encryptedData);
        if (!isHandshakeCompleted())
        {
            _handshaker.carryOn();
        }
    }

    /* Privates */

    private void attachCompletionListener()
    {
        _handshaker.addCompletedListener(new HandshakeCompletedListener()
        {
            @Override
            public void onComplete()
            {
                _handshaker = null;
                if (_hcl != null)
                {
                    _hcl.onComplete();
                    _hcl = null;
                }
            }
        });
    }

    private SSLEngine makeSSLEngine(SSLContext context, boolean client, boolean clientAuthRequired)
    {
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(client);
        engine.setNeedClientAuth(clientAuthRequired);
        return engine;
    }
}
