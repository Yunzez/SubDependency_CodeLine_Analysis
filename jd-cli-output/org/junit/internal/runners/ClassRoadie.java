package org.junit.internal.runners;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.internal.AssumptionViolatedException;
import org.junit.runner.Description;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunNotifier;

@Deprecated
public class ClassRoadie {
  private RunNotifier fNotifier;
  
  private TestClass fTestClass;
  
  private Description fDescription;
  
  private final Runnable fRunnable;
  
  public ClassRoadie(RunNotifier notifier, TestClass testClass, Description description, Runnable runnable) {
    this.fNotifier = notifier;
    this.fTestClass = testClass;
    this.fDescription = description;
    this.fRunnable = runnable;
  }
  
  protected void runUnprotected() {
    this.fRunnable.run();
  }
  
  protected void addFailure(Throwable targetException) {
    this.fNotifier.fireTestFailure(new Failure(this.fDescription, targetException));
  }
  
  public void runProtected() {
    try {
      runBefores();
      runUnprotected();
    } catch (FailedBefore e) {
    
    } finally {
      runAfters();
    } 
  }
  
  private void runBefores() throws FailedBefore {
    try {
      try {
        List<Method> befores = this.fTestClass.getBefores();
        for (Method before : befores)
          before.invoke(null, new Object[0]); 
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
    List<Method> afters = this.fTestClass.getAfters();
    for (Method after : afters) {
      try {
        after.invoke(null, new Object[0]);
      } catch (InvocationTargetException e) {
        addFailure(e.getTargetException());
      } catch (Throwable e) {
        addFailure(e);
      } 
    } 
  }
}
