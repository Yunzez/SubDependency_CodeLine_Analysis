package junit.textui;

import java.io.PrintStream;
import java.text.NumberFormat;
import java.util.Enumeration;
import junit.framework.AssertionFailedError;
import junit.framework.Test;
import junit.framework.TestFailure;
import junit.framework.TestListener;
import junit.framework.TestResult;
import junit.runner.BaseTestRunner;

public class ResultPrinter implements TestListener {
  PrintStream fWriter;
  
  int fColumn = 0;
  
  public ResultPrinter(PrintStream writer) {
    this.fWriter = writer;
  }
  
  synchronized void print(TestResult result, long runTime) {
    printHeader(runTime);
    printErrors(result);
    printFailures(result);
    printFooter(result);
  }
  
  void printWaitPrompt() {
    getWriter().println();
    getWriter().println("<RETURN> to continue");
  }
  
  protected void printHeader(long runTime) {
    getWriter().println();
    getWriter().println("Time: " + elapsedTimeAsString(runTime));
  }
  
  protected void printErrors(TestResult result) {
    printDefects(result.errors(), result.errorCount(), "error");
  }
  
  protected void printFailures(TestResult result) {
    printDefects(result.failures(), result.failureCount(), "failure");
  }
  
  protected void printDefects(Enumeration<TestFailure> booBoos, int count, String type) {
    if (count == 0)
      return; 
    if (count == 1) {
      getWriter().println("There was " + count + " " + type + ":");
    } else {
      getWriter().println("There were " + count + " " + type + "s:");
    } 
    for (int i = 1; booBoos.hasMoreElements(); i++)
      printDefect(booBoos.nextElement(), i); 
  }
  
  public void printDefect(TestFailure booBoo, int count) {
    printDefectHeader(booBoo, count);
    printDefectTrace(booBoo);
  }
  
  protected void printDefectHeader(TestFailure booBoo, int count) {
    getWriter().print(count + ") " + booBoo.failedTest());
  }
  
  protected void printDefectTrace(TestFailure booBoo) {
    getWriter().print(BaseTestRunner.getFilteredTrace(booBoo.trace()));
  }
  
  protected void printFooter(TestResult result) {
    if (result.wasSuccessful()) {
      getWriter().println();
      getWriter().print("OK");
      getWriter().println(" (" + result.runCount() + " test" + ((result.runCount() == 1) ? "" : "s") + ")");
    } else {
      getWriter().println();
      getWriter().println("FAILURES!!!");
      getWriter().println("Tests run: " + result.runCount() + ",  Failures: " + result.failureCount() + ",  Errors: " + result.errorCount());
    } 
    getWriter().println();
  }
  
  protected String elapsedTimeAsString(long runTime) {
    return NumberFormat.getInstance().format(runTime / 1000.0D);
  }
  
  public PrintStream getWriter() {
    return this.fWriter;
  }
  
  public void addError(Test test, Throwable t) {
    getWriter().print("E");
  }
  
  public void addFailure(Test test, AssertionFailedError t) {
    getWriter().print("F");
  }
  
  public void endTest(Test test) {}
  
  public void startTest(Test test) {
    getWriter().print(".");
    if (this.fColumn++ >= 40) {
      getWriter().println();
      this.fColumn = 0;
    } 
  }
}
