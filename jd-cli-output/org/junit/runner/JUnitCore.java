package org.junit.runner;

import java.util.ArrayList;
import java.util.List;
import junit.framework.Test;
import junit.runner.Version;
import org.junit.internal.JUnitSystem;
import org.junit.internal.RealSystem;
import org.junit.internal.TextListener;
import org.junit.internal.runners.JUnit38ClassRunner;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;

public class JUnitCore {
  private final RunNotifier fNotifier = new RunNotifier();
  
  public static void main(String... args) {
    runMainAndExit(new RealSystem(), args);
  }
  
  private static void runMainAndExit(JUnitSystem system, String... args) {
    Result result = (new JUnitCore()).runMain(system, args);
    System.exit(result.wasSuccessful() ? 0 : 1);
  }
  
  public static Result runClasses(Computer computer, Class<?>... classes) {
    return (new JUnitCore()).run(computer, classes);
  }
  
  public static Result runClasses(Class<?>... classes) {
    return (new JUnitCore()).run(defaultComputer(), classes);
  }
  
  private Result runMain(JUnitSystem system, String... args) {
    system.out().println("JUnit version " + Version.id());
    List<Class<?>> classes = new ArrayList<Class<?>>();
    List<Failure> missingClasses = new ArrayList<Failure>();
    for (String each : args) {
      try {
        classes.add(Class.forName(each));
      } catch (ClassNotFoundException e) {
        system.out().println("Could not find class: " + each);
        Description description = Description.createSuiteDescription(each, new java.lang.annotation.Annotation[0]);
        Failure failure = new Failure(description, e);
        missingClasses.add(failure);
      } 
    } 
    RunListener listener = new TextListener(system);
    addListener(listener);
    Result result = run((Class[])classes.<Class<?>[]>toArray((Class<?>[][])new Class[0]));
    for (Failure each : missingClasses)
      result.getFailures().add(each); 
    return result;
  }
  
  public String getVersion() {
    return Version.id();
  }
  
  public Result run(Class<?>... classes) {
    return run(Request.classes(defaultComputer(), classes));
  }
  
  public Result run(Computer computer, Class<?>... classes) {
    return run(Request.classes(computer, classes));
  }
  
  public Result run(Request request) {
    return run(request.getRunner());
  }
  
  public Result run(Test test) {
    return run(new JUnit38ClassRunner(test));
  }
  
  public Result run(Runner runner) {
    Result result = new Result();
    RunListener listener = result.createListener();
    this.fNotifier.addFirstListener(listener);
    try {
      this.fNotifier.fireTestRunStarted(runner.getDescription());
      runner.run(this.fNotifier);
      this.fNotifier.fireTestRunFinished(result);
    } finally {
      removeListener(listener);
    } 
    return result;
  }
  
  public void addListener(RunListener listener) {
    this.fNotifier.addListener(listener);
  }
  
  public void removeListener(RunListener listener) {
    this.fNotifier.removeListener(listener);
  }
  
  static Computer defaultComputer() {
    return new Computer();
  }
}
