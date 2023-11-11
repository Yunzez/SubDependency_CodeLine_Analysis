package junit.textui;

import java.io.PrintStream;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import junit.runner.BaseTestRunner;
import junit.runner.Version;

public class TestRunner extends BaseTestRunner {
  private ResultPrinter fPrinter;
  
  public static final int SUCCESS_EXIT = 0;
  
  public static final int FAILURE_EXIT = 1;
  
  public static final int EXCEPTION_EXIT = 2;
  
  public TestRunner() {
    this(System.out);
  }
  
  public TestRunner(PrintStream writer) {
    this(new ResultPrinter(writer));
  }
  
  public TestRunner(ResultPrinter printer) {
    this.fPrinter = printer;
  }
  
  public static void run(Class<? extends TestCase> testClass) {
    run(new TestSuite(testClass));
  }
  
  public static TestResult run(Test test) {
    TestRunner runner = new TestRunner();
    return runner.doRun(test);
  }
  
  public static void runAndWait(Test suite) {
    TestRunner aTestRunner = new TestRunner();
    aTestRunner.doRun(suite, true);
  }
  
  public void testFailed(int status, Test test, Throwable t) {}
  
  public void testStarted(String testName) {}
  
  public void testEnded(String testName) {}
  
  protected TestResult createTestResult() {
    return new TestResult();
  }
  
  public TestResult doRun(Test test) {
    return doRun(test, false);
  }
  
  public TestResult doRun(Test suite, boolean wait) {
    TestResult result = createTestResult();
    result.addListener(this.fPrinter);
    long startTime = System.currentTimeMillis();
    suite.run(result);
    long endTime = System.currentTimeMillis();
    long runTime = endTime - startTime;
    this.fPrinter.print(result, runTime);
    pause(wait);
    return result;
  }
  
  protected void pause(boolean wait) {
    if (!wait)
      return; 
    this.fPrinter.printWaitPrompt();
    try {
      System.in.read();
    } catch (Exception e) {}
  }
  
  public static void main(String[] args) {
    TestRunner aTestRunner = new TestRunner();
    try {
      TestResult r = aTestRunner.start(args);
      if (!r.wasSuccessful())
        System.exit(1); 
      System.exit(0);
    } catch (Exception e) {
      System.err.println(e.getMessage());
      System.exit(2);
    } 
  }
  
  public TestResult start(String[] args) throws Exception {
    String testCase = "";
    String method = "";
    boolean wait = false;
    for (int i = 0; i < args.length; i++) {
      if (args[i].equals("-wait")) {
        wait = true;
      } else if (args[i].equals("-c")) {
        testCase = extractClassName(args[++i]);
      } else if (args[i].equals("-m")) {
        String arg = args[++i];
        int lastIndex = arg.lastIndexOf('.');
        testCase = arg.substring(0, lastIndex);
        method = arg.substring(lastIndex + 1);
      } else if (args[i].equals("-v")) {
        System.err.println("JUnit " + Version.id() + " by Kent Beck and Erich Gamma");
      } else {
        testCase = args[i];
      } 
    } 
    if (testCase.equals(""))
      throw new Exception("Usage: TestRunner [-wait] testCaseName, where name is the name of the TestCase class"); 
    try {
      if (!method.equals(""))
        return runSingleMethod(testCase, method, wait); 
      Test suite = getTest(testCase);
      return doRun(suite, wait);
    } catch (Exception e) {
      throw new Exception("Could not create and run test suite: " + e);
    } 
  }
  
  protected TestResult runSingleMethod(String testCase, String method, boolean wait) throws Exception {
    Class<? extends TestCase> testClass = loadSuiteClass(testCase).asSubclass(TestCase.class);
    Test test = TestSuite.createTest(testClass, method);
    return doRun(test, wait);
  }
  
  protected void runFailed(String message) {
    System.err.println(message);
    System.exit(1);
  }
  
  public void setPrinter(ResultPrinter printer) {
    this.fPrinter = printer;
  }
}
