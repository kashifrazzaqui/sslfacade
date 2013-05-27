package prj.sslfacade;

import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

public class Buffers
{
    /*
     Buffers is a simple abstraction that creates the four ByteBuffers
     required to operate an SSLEngine. One way to look at the role of these
     buffers is that two of these buffers are used to process incoming data
     and the other two are used to process outgoing data. Another way to look
     at this is to say that two buffers represent the host application and two
     represent the peer application. The Java SSLEngine documentation calls
     these buffers application and network buffers and names them and refers
     to them variously but most commonly as myAppData, myNetData,
     peerAppData and peerNetData. I have used these same names for the private
     fields in this class so that the reader is able to associate them to the
     Java provided documentation with ease. For publically visible
     contracts, I felt better names were possible and have defined them
     in an enum called BufferType.

     In order to create an instance of Buffers all we need is a SSLSession.

     These buffers should not be reused by the host application for any
     other purpose as SSLEngine might modify the source buffer during an
     unwrap. Additionally, it is important to note that these buffers may
     have to be resized during operations and hence it is neither simple nor
     maintainable to allow the host application to inject its own buffers.
     In short, leave these Buffers alone!
     */

    private ByteBuffer _peerApp;
    private ByteBuffer _myApp;
    private ByteBuffer _peerNet;
    private ByteBuffer _myNet;
    private final SSLSession _session;

    public Buffers(SSLSession session)
    {
        /*
         The SSLSession needs to be saved as a private field because it is
         required when growing buffers.
         */
        _session = session;

        int applicationBufferSize = session.getApplicationBufferSize();
        int packetBufferSize = session.getPacketBufferSize();

        _peerApp = ByteBuffer.allocate(applicationBufferSize);
        _myApp = ByteBuffer.allocate(applicationBufferSize);
        _peerNet = ByteBuffer.allocate(packetBufferSize);
        _myNet = ByteBuffer.allocate(packetBufferSize);
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
                _peerApp = growOrCompact(t, _session.getApplicationBufferSize());
                break;
            case IN_CIPHER:
                _peerNet = growOrCompact(t, _session.getPacketBufferSize());
                break;
            case OUT_PLAIN:
                //No known reason for this case to occur
                break;
            case OUT_CIPHER:
                _myNet = growOrCompact(t, _session.getPacketBufferSize());
                break;
        }

    }

    private ByteBuffer growOrCompact(BufferType t, int recommendedBufferSize)
    {
        ByteBuffer originalBuffer = get(t);
        if (recommendedBufferSize > originalBuffer.capacity())
        {
            return grow(recommendedBufferSize, originalBuffer);

        }
        else
        {
            //if its already big enough,lets compact it
            return compact(originalBuffer);
        }
    }

    private ByteBuffer compact(ByteBuffer originalBuffer)
    {
        originalBuffer.compact();
        return originalBuffer;
    }

    private ByteBuffer grow(int recommendedBufferSize, ByteBuffer originalBuffer)
    {
        //growth strategy is to make it atleast as big
        ByteBuffer newBuffer = ByteBuffer.allocate(recommendedBufferSize);
        originalBuffer.flip();
        newBuffer.put(originalBuffer);
        return newBuffer;
    }
}
