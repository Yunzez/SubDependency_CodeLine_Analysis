package org.bouncycastle.util.test;

import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.util.Arrays;

public abstract class SimpleTest implements Test {
  public abstract String getName();
  
  private TestResult success() {
    return SimpleTestResult.successful(this, "Okay");
  }
  
  protected void fail(String paramString) {
    throw new TestFailedException(SimpleTestResult.failed(this, paramString));
  }
  
  protected void isTrue(boolean paramBoolean) {
    if (!paramBoolean)
      throw new TestFailedException(SimpleTestResult.failed(this, "no message")); 
  }
  
  protected void isTrue(String paramString, boolean paramBoolean) {
    if (!paramBoolean)
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
  }
  
  protected void isEquals(Object paramObject1, Object paramObject2) {
    if (!paramObject1.equals(paramObject2))
      throw new TestFailedException(SimpleTestResult.failed(this, "no message")); 
  }
  
  protected void isEquals(int paramInt1, int paramInt2) {
    if (paramInt1 != paramInt2)
      throw new TestFailedException(SimpleTestResult.failed(this, "no message")); 
  }
  
  protected void isEquals(long paramLong1, long paramLong2) {
    if (paramLong1 != paramLong2)
      throw new TestFailedException(SimpleTestResult.failed(this, "no message")); 
  }
  
  protected void isEquals(String paramString, boolean paramBoolean1, boolean paramBoolean2) {
    if (paramBoolean1 != paramBoolean2)
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
  }
  
  protected void isEquals(String paramString, long paramLong1, long paramLong2) {
    if (paramLong1 != paramLong2)
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
  }
  
  protected void isEquals(String paramString, Object paramObject1, Object paramObject2) {
    if (paramObject1 == null && paramObject2 == null)
      return; 
    if (paramObject1 == null)
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
    if (paramObject2 == null)
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
    if (!paramObject1.equals(paramObject2))
      throw new TestFailedException(SimpleTestResult.failed(this, paramString)); 
  }
  
  protected boolean areEqual(byte[][] paramArrayOfbyte1, byte[][] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == null && paramArrayOfbyte2 == null)
      return true; 
    if (paramArrayOfbyte1 == null || paramArrayOfbyte2 == null)
      return false; 
    if (paramArrayOfbyte1.length != paramArrayOfbyte2.length)
      return false; 
    byte b = 0;
    while (b < paramArrayOfbyte1.length) {
      if (areEqual(paramArrayOfbyte1[b], paramArrayOfbyte2[b])) {
        b++;
        continue;
      } 
      return false;
    } 
    return true;
  }
  
  protected void fail(String paramString, Throwable paramThrowable) {
    throw new TestFailedException(SimpleTestResult.failed(this, paramString, paramThrowable));
  }
  
  protected void fail(String paramString, Object paramObject1, Object paramObject2) {
    throw new TestFailedException(SimpleTestResult.failed(this, paramString, paramObject1, paramObject2));
  }
  
  protected boolean areEqual(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    return Arrays.areEqual(paramArrayOfbyte1, paramArrayOfbyte2);
  }
  
  protected boolean areEqual(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    return Arrays.areEqual(paramArrayOfbyte1, paramInt1, paramInt2, paramArrayOfbyte2, paramInt3, paramInt4);
  }
  
  public TestResult perform() {
    try {
      performTest();
      return success();
    } catch (TestFailedException testFailedException) {
      return testFailedException.getResult();
    } catch (Exception exception) {
      return SimpleTestResult.failed(this, "Exception: " + exception, exception);
    } 
  }
  
  public abstract void performTest() throws Exception;
  
  public static void runTest(Test paramTest) {
    runTest(paramTest, System.out);
  }
  
  public static void runTest(Test paramTest, PrintStream paramPrintStream) {
    TestResult testResult = paramTest.perform();
    if (testResult.getException() != null)
      testResult.getException().printStackTrace(paramPrintStream); 
    paramPrintStream.println(testResult);
  }
  
  public static void runTests(Test[] paramArrayOfTest) {
    runTests(paramArrayOfTest, System.out);
  }
  
  public static void runTests(Test[] paramArrayOfTest, PrintStream paramPrintStream) {
    Vector<TestResult> vector = new Vector();
    for (byte b = 0; b != paramArrayOfTest.length; b++) {
      TestResult testResult = paramArrayOfTest[b].perform();
      if (!testResult.isSuccessful())
        vector.addElement(testResult); 
      if (testResult.getException() != null)
        testResult.getException().printStackTrace(paramPrintStream); 
      paramPrintStream.println(testResult);
    } 
    paramPrintStream.println("-----");
    if (vector.isEmpty()) {
      paramPrintStream.println("All tests successful.");
    } else {
      paramPrintStream.println("Completed with " + vector.size() + " FAILURES:");
      Enumeration<TestResult> enumeration = vector.elements();
      while (enumeration.hasMoreElements())
        System.out.println("=>  " + (TestResult)enumeration.nextElement()); 
    } 
  }
}
