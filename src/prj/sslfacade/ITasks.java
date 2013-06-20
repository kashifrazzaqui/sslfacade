package prj.sslfacade;

import java.io.IOException;

public interface ITasks
{
    Runnable next();

    void done() throws IOException;
}
