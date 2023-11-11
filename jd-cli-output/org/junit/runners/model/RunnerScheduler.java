package org.junit.runners.model;

public interface RunnerScheduler {
  void schedule(Runnable paramRunnable);
  
  void finished();
}
