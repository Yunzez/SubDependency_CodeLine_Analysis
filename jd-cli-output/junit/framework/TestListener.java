package junit.framework;

public interface TestListener {
  void addError(Test paramTest, Throwable paramThrowable);
  
  void addFailure(Test paramTest, AssertionFailedError paramAssertionFailedError);
  
  void endTest(Test paramTest);
  
  void startTest(Test paramTest);
}
