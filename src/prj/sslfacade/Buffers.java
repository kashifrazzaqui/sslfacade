package prj.sslfacade;

import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

public class Buffers
{
    private ByteBuffer _peerApp;
    private ByteBuffer _myApp;
    private ByteBuffer _peerNet;
    private ByteBuffer _myNet;
    private final SSLSession _session;

    public Buffers(SSLSession session)
    {
        _session = session;
        _peerApp = ByteBuffer.allocate(session.getApplicationBufferSize());
        _myApp = ByteBuffer.allocate(session.getApplicationBufferSize());
        _peerNet = ByteBuffer.allocate(session.getPacketBufferSize());
        _myNet = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    public ByteBuffer get(BufferType t)
    {
        ByteBuffer result = null;
        switch (t)
        {
            case IN_PLAIN:
                result = _peerApp;
                break;
            case IN_CIPHER:
                result = _peerNet;
                break;
            case OUT_PLAIN:
                result = _myApp;
                break;
            case OUT_CIPHER:
                result = _myNet;
                break;
        }
        return result;
    }

    public void manage(BufferType t)
    {
        //TODO
        switch (t)
        {
            case IN_PLAIN:
                //an unwrap had a buffer overflow
                _peerApp = growOrCompact(t, _session.getApplicationBufferSize());
                break;
            case IN_CIPHER:
                //an unwrap had a buffer underflow
                _peerNet = growOrCompact(t, _session.getPacketBufferSize());
                break;
            case OUT_PLAIN:
                //a wrap had a buffer underflow - when is this possible?
                //you called wrap without giving it data to wrap?
                //TODO - remove this RuntimeEx
                throw new RuntimeException("ERROR: Buffer underflow in a wrap!");
            case OUT_CIPHER:
                //a wrap had a buffer overflow
                _myNet = growOrCompact(t, _session.getPacketBufferSize());
                break;
        }

    }

    private ByteBuffer growOrCompact(BufferType t, int recommendedBufferSize)
    {
        ByteBuffer originalBuffer = get(t);
        if (recommendedBufferSize > originalBuffer.capacity())
        {
            //growth strategy is to make it atleast as big
            ByteBuffer newBuffer = ByteBuffer.allocate(recommendedBufferSize);
            originalBuffer.flip();
            newBuffer.put(originalBuffer);
            return newBuffer;
        }
        else
        {
            //if its already big enough,lets compact it
            originalBuffer.compact();
            return originalBuffer;
        }
    }
}
