package prj.sslfacade;

public class InsufficentUnwrapData extends Throwable
{
    private final String _message;

    public InsufficentUnwrapData(String s)
    {
        _message = s;
    }

    @Override
    public String getMessage()
    {
        return _message;
    }
}
