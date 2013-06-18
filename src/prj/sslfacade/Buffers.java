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
     In short, leave these buffers alone!
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
        allocate();
    }

    public void resetAllBufferSizes()
    {
        allocate();
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

    public void assign(BufferType t, ByteBuffer b)
    {
        switch (t)
        {

            case IN_PLAIN:
                _peerApp = b;
                break;
            case IN_CIPHER:
                _peerNet = b;
                break;
            case OUT_PLAIN:
                _myApp = b;
                break;
            case OUT_CIPHER:
                _myNet = b;
                break;
        }
    }

    public void grow(BufferType t)
    {
        //TODO
        switch (t)
        {
            case IN_PLAIN:
                assign(t, grow(t,
                        _session.getApplicationBufferSize()));
                break;
            case IN_CIPHER:
                assign(t, grow(t, _session.getPacketBufferSize()));
                break;
            case OUT_PLAIN:
                //No known reason for this case to occur
                break;
            case OUT_CIPHER:
                assign(t, grow(t, _session.getPacketBufferSize()));
                break;
        }

    }

    public void resetSize(BufferType t, int size)
    {
        ByteBuffer newBuffer = ByteBuffer.allocate(size);
        copy(get(t), newBuffer);
        assign(t, newBuffer);
    }

    private void growIfNecessary(BufferType t, int size)
    {
        //grow if not enough space
        ByteBuffer b = get(t);
        if (b.capacity() < size)
        {
            resetSize(t, size);
        }
    }

    public ByteBuffer grow(BufferType b, int recommendedBufferSize)
    {
        /*
        guaranteed to grow the buffer to the minimum recommended size or
        more. If the buffer is at the recommended minimum size we could
        still be facing repeated overflows because the host application
        might misbehave or be incapable of draining the buffer in
        an appropriate fashion - we expect the host application to fix this.
        */
        ByteBuffer originalBuffer = get(b);
        ByteBuffer newBuffer = ByteBuffer.allocate(recommendedBufferSize);
        copy(originalBuffer, newBuffer);
        return newBuffer;
    }

    public void copy(ByteBuffer from, ByteBuffer to)
    {
        from.rewind();
        to.put(from);
    }

    private void allocate()
    {
        int applicationBufferSize = _session.getApplicationBufferSize();
        int packetBufferSize = _session.getPacketBufferSize();
        _peerApp = ByteBuffer.allocate(applicationBufferSize);
        _myApp = ByteBuffer.allocate(applicationBufferSize);
        _peerNet = ByteBuffer.allocate(packetBufferSize);
        _myNet = ByteBuffer.allocate(packetBufferSize);
    }

    public void prepareForUnwrap(ByteBuffer data)
    {
        clear(BufferType.IN_CIPHER, BufferType.IN_PLAIN);
        if (data != null)
        {
            growIfNecessary(BufferType.IN_CIPHER, data.capacity());
            get(BufferType.IN_CIPHER).put(data);
        }
    }

    public void prepareForWrap(ByteBuffer data)
    {
        //Avoid buffer overflow when loading plain data and clear buffers
        clear(BufferType.OUT_PLAIN, BufferType.OUT_CIPHER);
        if (data != null)
        {
            growIfNecessary(BufferType.OUT_PLAIN, data.capacity());
            get(BufferType.OUT_PLAIN).put(data);
        }
    }

    public void prepareRetrial(BufferType source, BufferType destination)
    {
        get(source).rewind();
        get(destination).clear();
    }

    private void clear(BufferType source, BufferType destination)
    {
        get(source).clear();
        get(destination).clear();
    }

}
