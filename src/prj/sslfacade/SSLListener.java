package prj.sslfacade;

import java.nio.ByteBuffer;

public interface SSLListener
{
    public void onWrappedData(ByteBuffer wrappedBytes);
    public void onPlainData(ByteBuffer plainBytes);
}
