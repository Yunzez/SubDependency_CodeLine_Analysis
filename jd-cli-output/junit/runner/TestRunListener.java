package junit.runner;

public interface TestRunListener {
  public static final int STATUS_ERROR = 1;
  
  public static final int STATUS_FAILURE = 2;
  
  void testRunStarted(String paramString, int paramInt);
  
  void testRunEnded(long paramLong);
  
  void testRunStopped(long paramLong);
  
  void testStarted(String paramString);
  
  void testEnded(String paramString);
  
  void testFailed(int paramInt, String paramString1, String paramString2);
}
