package prj.sslfacade;

import java.nio.ByteBuffer;

public class AppendableBuffer
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
        _ = ByteBuffer.allocate(data.limit());
        _.put(data);
    }

    public void clear()
    {
        if (notNull())
        {
            _.clear();
        }
    }

    /* private */

    private int calculateSize(ByteBuffer data)
    {
        int result = data.capacity();
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

}
