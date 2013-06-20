package prj.sslfacade;

import java.nio.ByteBuffer;

class AppendableBuffer
{
    private ByteBuffer _;

    public ByteBuffer append(ByteBuffer data)
    {
        ByteBuffer nb = ByteBuffer.allocate(calculateSize(data));
        if (notNull())
        {
            nb.put(_);
            clear();
        }
        nb.put(data);
        return nb;
    }

    public void set(ByteBuffer data)
    {
        if (data.hasRemaining())
        {
            _ = ByteBuffer.allocate(data.remaining());
            _.put(data);
            _.rewind();
        }
    }

    public void clear()
    {
        _ = null;
    }

    /* private */

    private int calculateSize(ByteBuffer data)
    {
        int result = data.limit();
        if (notNull())
        {
            result += _.capacity();
        }
        return result;
    }

    private boolean notNull()
    {
        return _ != null;
    }

    public boolean hasRemaining()
    {
        if (notNull())
        {
            return _.hasRemaining();
        }
        return false;
    }

    public ByteBuffer get()
    {
        return _;
    }
}
