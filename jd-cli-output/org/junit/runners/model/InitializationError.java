package org.junit.runners.model;

import java.util.Arrays;
import java.util.List;

public class InitializationError extends Exception {
  private static final long serialVersionUID = 1L;
  
  private final List<Throwable> fErrors;
  
  public InitializationError(List<Throwable> errors) {
    this.fErrors = errors;
  }
  
  public InitializationError(Throwable error) {
    this(Arrays.asList(new Throwable[] { error }));
  }
  
  public InitializationError(String string) {
    this(new Exception(string));
  }
  
  public List<Throwable> getCauses() {
    return this.fErrors;
  }
}
