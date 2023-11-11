package org.junit.internal.requests;

import org.junit.internal.builders.AllDefaultPossibilitiesBuilder;
import org.junit.runner.Request;
import org.junit.runner.Runner;

public class ClassRequest extends Request {
  private final Object fRunnerLock = new Object();
  
  private final Class<?> fTestClass;
  
  private final boolean fCanUseSuiteMethod;
  
  private Runner fRunner;
  
  public ClassRequest(Class<?> testClass, boolean canUseSuiteMethod) {
    this.fTestClass = testClass;
    this.fCanUseSuiteMethod = canUseSuiteMethod;
  }
  
  public ClassRequest(Class<?> testClass) {
    this(testClass, true);
  }
  
  public Runner getRunner() {
    synchronized (this.fRunnerLock) {
      if (this.fRunner == null)
        this.fRunner = (new AllDefaultPossibilitiesBuilder(this.fCanUseSuiteMethod)).safeRunnerForClass(this.fTestClass); 
      return this.fRunner;
    } 
  }
}
