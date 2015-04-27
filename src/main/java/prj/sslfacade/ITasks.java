package prj.sslfacade;

import javax.net.ssl.SSLException;

public interface ITasks
{
    Runnable next();

    void done() throws SSLException;
}
