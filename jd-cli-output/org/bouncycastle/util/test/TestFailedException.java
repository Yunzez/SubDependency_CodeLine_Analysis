package org.bouncycastle.util.test;

public class TestFailedException extends RuntimeException {
  private TestResult _result;
  
  public TestFailedException(TestResult paramTestResult) {
    this._result = paramTestResult;
  }
  
  public TestResult getResult() {
    return this._result;
  }
}
