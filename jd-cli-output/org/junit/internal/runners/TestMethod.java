package org.junit.internal.runners;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

@Deprecated
public class TestMethod {
  private final Method fMethod;
  
  private TestClass fTestClass;
  
  public TestMethod(Method method, TestClass testClass) {
    this.fMethod = method;
    this.fTestClass = testClass;
  }
  
  public boolean isIgnored() {
    return (this.fMethod.getAnnotation(Ignore.class) != null);
  }
  
  public long getTimeout() {
    Test annotation = this.fMethod.<Test>getAnnotation(Test.class);
    if (annotation == null)
      return 0L; 
    long timeout = annotation.timeout();
    return timeout;
  }
  
  protected Class<? extends Throwable> getExpectedException() {
    Test annotation = this.fMethod.<Test>getAnnotation(Test.class);
    if (annotation == null || annotation.expected() == Test.None.class)
      return null; 
    return annotation.expected();
  }
  
  boolean isUnexpected(Throwable exception) {
    return !getExpectedException().isAssignableFrom(exception.getClass());
  }
  
  boolean expectsException() {
    return (getExpectedException() != null);
  }
  
  List<Method> getBefores() {
    return this.fTestClass.getAnnotatedMethods((Class)Before.class);
  }
  
  List<Method> getAfters() {
    return this.fTestClass.getAnnotatedMethods((Class)After.class);
  }
  
  public void invoke(Object test) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
    this.fMethod.invoke(test, new Object[0]);
  }
}
