package org.junit.runner.notification;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.junit.runner.Description;
import org.junit.runner.Result;

public class RunNotifier {
  private final List<RunListener> fListeners = Collections.synchronizedList(new ArrayList<RunListener>());
  
  private volatile boolean fPleaseStop = false;
  
  public void addListener(RunListener listener) {
    this.fListeners.add(listener);
  }
  
  public void removeListener(RunListener listener) {
    this.fListeners.remove(listener);
  }
  
  private abstract class SafeNotifier {
    private final List<RunListener> fCurrentListeners;
    
    SafeNotifier() {
      this(RunNotifier.this.fListeners);
    }
    
    SafeNotifier(List<RunListener> currentListeners) {
      this.fCurrentListeners = currentListeners;
    }
    
    void run() {
      synchronized (RunNotifier.this.fListeners) {
        List<RunListener> safeListeners = new ArrayList<RunListener>();
        List<Failure> failures = new ArrayList<Failure>();
        Iterator<RunListener> all = this.fCurrentListeners.iterator();
        while (all.hasNext()) {
          try {
            RunListener listener = all.next();
            notifyListener(listener);
            safeListeners.add(listener);
          } catch (Exception e) {
            failures.add(new Failure(Description.TEST_MECHANISM, e));
          } 
        } 
        RunNotifier.this.fireTestFailures(safeListeners, failures);
      } 
    }
    
    protected abstract void notifyListener(RunListener param1RunListener) throws Exception;
  }
  
  public void fireTestRunStarted(final Description description) {
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testRunStarted(description);
        }
      }).run();
  }
  
  public void fireTestRunFinished(final Result result) {
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testRunFinished(result);
        }
      }).run();
  }
  
  public void fireTestStarted(final Description description) throws StoppedByUserException {
    if (this.fPleaseStop)
      throw new StoppedByUserException(); 
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testStarted(description);
        }
      }).run();
  }
  
  public void fireTestFailure(Failure failure) {
    fireTestFailures(this.fListeners, Arrays.asList(new Failure[] { failure }));
  }
  
  private void fireTestFailures(List<RunListener> listeners, final List<Failure> failures) {
    if (!failures.isEmpty())
      (new SafeNotifier(listeners) {
          protected void notifyListener(RunListener listener) throws Exception {
            for (Failure each : failures)
              listener.testFailure(each); 
          }
        }).run(); 
  }
  
  public void fireTestAssumptionFailed(final Failure failure) {
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testAssumptionFailure(failure);
        }
      }).run();
  }
  
  public void fireTestIgnored(final Description description) {
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testIgnored(description);
        }
      }).run();
  }
  
  public void fireTestFinished(final Description description) {
    (new SafeNotifier() {
        protected void notifyListener(RunListener each) throws Exception {
          each.testFinished(description);
        }
      }).run();
  }
  
  public void pleaseStop() {
    this.fPleaseStop = true;
  }
  
  public void addFirstListener(RunListener listener) {
    this.fListeners.add(0, listener);
  }
}
