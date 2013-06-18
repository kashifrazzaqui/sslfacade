package prj.sslfacade;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface HostTransport
{
    void send(ByteBuffer data) throws IOException;
}
