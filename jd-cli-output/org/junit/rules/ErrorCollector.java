package org.junit.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import org.hamcrest.Matcher;
import org.junit.Assert;
import org.junit.runners.model.MultipleFailureException;

public class ErrorCollector extends Verifier {
  private List<Throwable> errors = new ArrayList<Throwable>();
  
  protected void verify() throws Throwable {
    MultipleFailureException.assertEmpty(this.errors);
  }
  
  public void addError(Throwable error) {
    this.errors.add(error);
  }
  
  public <T> void checkThat(T value, Matcher<T> matcher) {
    checkThat("", value, matcher);
  }
  
  public <T> void checkThat(final String reason, final T value, final Matcher<T> matcher) {
    checkSucceeds(new Callable() {
          public Object call() throws Exception {
            Assert.assertThat(reason, value, matcher);
            return value;
          }
        });
  }
  
  public Object checkSucceeds(Callable<Object> callable) {
    try {
      return callable.call();
    } catch (Throwable e) {
      addError(e);
      return null;
    } 
  }
}
