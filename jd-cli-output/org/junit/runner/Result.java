package org.junit.runner;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

public class Result implements Serializable {
  private static final long serialVersionUID = 1L;
  
  private AtomicInteger fCount = new AtomicInteger();
  
  private AtomicInteger fIgnoreCount = new AtomicInteger();
  
  private final List<Failure> fFailures = Collections.synchronizedList(new ArrayList<Failure>());
  
  private long fRunTime = 0L;
  
  private long fStartTime;
  
  public int getRunCount() {
    return this.fCount.get();
  }
  
  public int getFailureCount() {
    return this.fFailures.size();
  }
  
  public long getRunTime() {
    return this.fRunTime;
  }
  
  public List<Failure> getFailures() {
    return this.fFailures;
  }
  
  public int getIgnoreCount() {
    return this.fIgnoreCount.get();
  }
  
  public boolean wasSuccessful() {
    return (getFailureCount() == 0);
  }
  
  private class Listener extends RunListener {
    private Listener() {}
    
    public void testRunStarted(Description description) throws Exception {
      Result.this.fStartTime = System.currentTimeMillis();
    }
    
    public void testRunFinished(Result result) throws Exception {
      long endTime = System.currentTimeMillis();
      Result.this.fRunTime += endTime - Result.this.fStartTime;
    }
    
    public void testFinished(Description description) throws Exception {
      Result.this.fCount.getAndIncrement();
    }
    
    public void testFailure(Failure failure) throws Exception {
      Result.this.fFailures.add(failure);
    }
    
    public void testIgnored(Description description) throws Exception {
      Result.this.fIgnoreCount.getAndIncrement();
    }
    
    public void testAssumptionFailure(Failure failure) {}
  }
  
  public RunListener createListener() {
    return new Listener();
  }
}
