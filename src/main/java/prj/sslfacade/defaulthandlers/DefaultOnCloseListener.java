package prj.sslfacade.defaulthandlers;

import prj.sslfacade.ISessionClosedListener;

/** By default do nothing on the close event.
 *
 */
public class DefaultOnCloseListener implements ISessionClosedListener
{
  @Override
  public void onSessionClosed()
  {
  } 
}
