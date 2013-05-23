package old;

import java.io.IOException;

public interface SSLTransport<T>
{
    void send(T userId, byte[] data) throws IOException;
}
