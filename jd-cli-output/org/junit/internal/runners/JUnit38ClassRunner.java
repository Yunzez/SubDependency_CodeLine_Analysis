package org.junit.internal.runners;

import junit.extensions.TestDecorator;
import junit.framework.AssertionFailedError;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestListener;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import org.junit.runner.Describable;
import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.manipulation.Filter;
import org.junit.runner.manipulation.Filterable;
import org.junit.runner.manipulation.NoTestsRemainException;
import org.junit.runner.manipulation.Sortable;
import org.junit.runner.manipulation.Sorter;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunNotifier;

public class JUnit38ClassRunner extends Runner implements Filterable, Sortable {
  private Test fTest;
  
  private final class OldTestClassAdaptingListener implements TestListener {
    private final RunNotifier fNotifier;
    
    private OldTestClassAdaptingListener(RunNotifier notifier) {
      this.fNotifier = notifier;
    }
    
    public void endTest(Test test) {
      this.fNotifier.fireTestFinished(asDescription(test));
    }
    
    public void startTest(Test test) {
      this.fNotifier.fireTestStarted(asDescription(test));
    }
    
    public void addError(Test test, Throwable t) {
      Failure failure = new Failure(asDescription(test), t);
      this.fNotifier.fireTestFailure(failure);
    }
    
    private Description asDescription(Test test) {
      if (test instanceof Describable) {
        Describable facade = (Describable)test;
        return facade.getDescription();
      } 
      return Description.createTestDescription(getEffectiveClass(test), getName(test));
    }
    
    private Class<? extends Test> getEffectiveClass(Test test) {
      return (Class)test.getClass();
    }
    
    private String getName(Test test) {
      if (test instanceof TestCase)
        return ((TestCase)test).getName(); 
      return test.toString();
    }
    
    public void addFailure(Test test, AssertionFailedError t) {
      addError(test, t);
    }
  }
  
  public JUnit38ClassRunner(Class<?> klass) {
    this(new TestSuite(klass.asSubclass(TestCase.class)));
  }
  
  public JUnit38ClassRunner(Test test) {
    setTest(test);
  }
  
  public void run(RunNotifier notifier) {
    TestResult result = new TestResult();
    result.addListener(createAdaptingListener(notifier));
    getTest().run(result);
  }
  
  public TestListener createAdaptingListener(RunNotifier notifier) {
    return new OldTestClassAdaptingListener(notifier);
  }
  
  public Description getDescription() {
    return makeDescription(getTest());
  }
  
  private static Description makeDescription(Test test) {
    if (test instanceof TestCase) {
      TestCase tc = (TestCase)test;
      return Description.createTestDescription(tc.getClass(), tc.getName());
    } 
    if (test instanceof TestSuite) {
      TestSuite ts = (TestSuite)test;
      String name = (ts.getName() == null) ? createSuiteDescription(ts) : ts.getName();
      Description description = Description.createSuiteDescription(name, new java.lang.annotation.Annotation[0]);
      int n = ts.testCount();
      for (int i = 0; i < n; i++) {
        Description made = makeDescription(ts.testAt(i));
        description.addChild(made);
      } 
      return description;
    } 
    if (test instanceof Describable) {
      Describable adapter = (Describable)test;
      return adapter.getDescription();
    } 
    if (test instanceof TestDecorator) {
      TestDecorator decorator = (TestDecorator)test;
      return makeDescription(decorator.getTest());
    } 
    return Description.createSuiteDescription(test.getClass());
  }
  
  private static String createSuiteDescription(TestSuite ts) {
    int count = ts.countTestCases();
    String example = (count == 0) ? "" : String.format(" [example: %s]", new Object[] { ts.testAt(0) });
    return String.format("TestSuite with %s tests%s", new Object[] { Integer.valueOf(count), example });
  }
  
  public void filter(Filter filter) throws NoTestsRemainException {
    if (getTest() instanceof Filterable) {
      Filterable adapter = (Filterable)getTest();
      adapter.filter(filter);
    } else if (getTest() instanceof TestSuite) {
      TestSuite suite = (TestSuite)getTest();
      TestSuite filtered = new TestSuite(suite.getName());
      int n = suite.testCount();
      for (int i = 0; i < n; i++) {
        Test test = suite.testAt(i);
        if (filter.shouldRun(makeDescription(test)))
          filtered.addTest(test); 
      } 
      setTest(filtered);
    } 
  }
  
  public void sort(Sorter sorter) {
    if (getTest() instanceof Sortable) {
      Sortable adapter = (Sortable)getTest();
      adapter.sort(sorter);
    } 
  }
  
  private void setTest(Test test) {
    this.fTest = test;
  }
  
  private Test getTest() {
    return this.fTest;
  }
}
