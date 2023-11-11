package org.junit.internal.runners;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import junit.framework.Test;

public class SuiteMethod extends JUnit38ClassRunner {
  public SuiteMethod(Class<?> klass) throws Throwable {
    super(testFromSuiteMethod(klass));
  }
  
  public static Test testFromSuiteMethod(Class<?> klass) throws Throwable {
    Method suiteMethod = null;
    Test suite = null;
    try {
      suiteMethod = klass.getMethod("suite", new Class[0]);
      if (!Modifier.isStatic(suiteMethod.getModifiers()))
        throw new Exception(klass.getName() + ".suite() must be static"); 
      suite = (Test)suiteMethod.invoke(null, new Object[0]);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    } 
    return suite;
  }
}
