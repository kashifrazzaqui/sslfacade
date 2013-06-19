package prj.sslfacade;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class SSLFacade
{
    private Handshaker _handshaker;
    private HandshakeCompletedListener _hcl;
    private final Worker _worker;

    public SSLFacade(SSLContext context, boolean client,
                     boolean clientAuthRequired, TaskHandler taskHandler)
    {
        //TODO: Host, port stuff
        SSLEngine engine = makeSSLEngine(context, client, clientAuthRequired);
        Buffers buffers = new Buffers(engine.getSession());
        _worker = new Worker(engine, buffers);
        _handshaker = new Handshaker(_worker, taskHandler);
    }

    public void beginHandshake() throws IOException
    {
        attachCompletionListener();
        try
        {
            _handshaker.begin();
        }
        catch (InsufficentUnwrapData ignored)
        {
            //When more data arrives try again
        }
    }

    public void setHandshakeCompletedListener(HandshakeCompletedListener hcl)
    {
        _hcl = hcl;
    }

    public void setSSLListener(SSLListener l)
    {
        _worker.setSSLListener(l);
    }

    public boolean isHandshakeCompleted()
    {
        return _handshaker == null || _handshaker.isFinished();
    }

    public void encrypt(ByteBuffer plainData) throws SSLException
    {
        _worker.wrap(plainData);
    }


    public void decrypt(ByteBuffer encryptedData) throws SSLException
    {
        _worker.unwrap(encryptedData);
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
