package org.junit.internal.runners;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.internal.AssumptionViolatedException;
import org.junit.runner.Description;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunNotifier;

@Deprecated
public class MethodRoadie {
  private final Object fTest;
  
  private final RunNotifier fNotifier;
  
  private final Description fDescription;
  
  private TestMethod fTestMethod;
  
  public MethodRoadie(Object test, TestMethod method, RunNotifier notifier, Description description) {
    this.fTest = test;
    this.fNotifier = notifier;
    this.fDescription = description;
    this.fTestMethod = method;
  }
  
  public void run() {
    if (this.fTestMethod.isIgnored()) {
      this.fNotifier.fireTestIgnored(this.fDescription);
      return;
    } 
    this.fNotifier.fireTestStarted(this.fDescription);
    try {
      long timeout = this.fTestMethod.getTimeout();
      if (timeout > 0L) {
        runWithTimeout(timeout);
      } else {
        runTest();
      } 
    } finally {
      this.fNotifier.fireTestFinished(this.fDescription);
    } 
  }
  
  private void runWithTimeout(final long timeout) {
    runBeforesThenTestThenAfters(new Runnable() {
          public void run() {
            ExecutorService service = Executors.newSingleThreadExecutor();
            Callable<Object> callable = new Callable() {
                public Object call() throws Exception {
                  MethodRoadie.this.runTestMethod();
                  return null;
                }
              };
            Future<Object> result = service.submit(callable);
            service.shutdown();
            try {
              boolean terminated = service.awaitTermination(timeout, TimeUnit.MILLISECONDS);
              if (!terminated)
                service.shutdownNow(); 
              result.get(0L, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
              MethodRoadie.this.addFailure(new Exception(String.format("test timed out after %d milliseconds", new Object[] { Long.valueOf(this.val$timeout) })));
            } catch (Exception e) {
              MethodRoadie.this.addFailure(e);
            } 
          }
        });
  }
  
  public void runTest() {
    runBeforesThenTestThenAfters(new Runnable() {
          public void run() {
            MethodRoadie.this.runTestMethod();
          }
        });
  }
  
  public void runBeforesThenTestThenAfters(Runnable test) {
    try {
      runBefores();
      test.run();
    } catch (FailedBefore e) {
    
    } catch (Exception e) {
      throw new RuntimeException("test should never throw an exception to this level");
    } finally {
      runAfters();
    } 
  }
  
  protected void runTestMethod() {
    try {
      this.fTestMethod.invoke(this.fTest);
      if (this.fTestMethod.expectsException())
        addFailure(new AssertionError("Expected exception: " + this.fTestMethod.getExpectedException().getName())); 
    } catch (InvocationTargetException e) {
      Throwable actual = e.getTargetException();
      if (actual instanceof AssumptionViolatedException)
        return; 
      if (!this.fTestMethod.expectsException()) {
        addFailure(actual);
      } else if (this.fTestMethod.isUnexpected(actual)) {
        String message = "Unexpected exception, expected<" + this.fTestMethod.getExpectedException().getName() + "> but was<" + actual.getClass().getName() + ">";
        addFailure(new Exception(message, actual));
      } 
    } catch (Throwable e) {
      addFailure(e);
    } 
  }
  
  private void runBefores() throws FailedBefore {
    try {
      try {
        List<Method> befores = this.fTestMethod.getBefores();
        for (Method before : befores)
          before.invoke(this.fTest, new Object[0]); 
      } catch (InvocationTargetException e) {
        throw e.getTargetException();
      } 
    } catch (AssumptionViolatedException e) {
      throw new FailedBefore();
    } catch (Throwable e) {
      addFailure(e);
      throw new FailedBefore();
    } 
  }
  
  private void runAfters() {
    List<Method> afters = this.fTestMethod.getAfters();
    for (Method after : afters) {
      try {
        after.invoke(this.fTest, new Object[0]);
      } catch (InvocationTargetException e) {
        addFailure(e.getTargetException());
      } catch (Throwable e) {
        addFailure(e);
      } 
    } 
  }
  
  protected void addFailure(Throwable e) {
    this.fNotifier.fireTestFailure(new Failure(this.fDescription, e));
  }
}
