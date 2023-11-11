package org.junit.rules;

import java.util.ArrayList;
import java.util.List;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.matchers.JUnitMatchers;

class ExpectedExceptionMatcherBuilder {
  private final List<Matcher<?>> fMatchers = new ArrayList<Matcher<?>>();
  
  void add(Matcher<?> matcher) {
    this.fMatchers.add(matcher);
  }
  
  boolean expectsThrowable() {
    return !this.fMatchers.isEmpty();
  }
  
  Matcher<Throwable> build() {
    return JUnitMatchers.isThrowable(allOfTheMatchers());
  }
  
  private Matcher<Throwable> allOfTheMatchers() {
    if (this.fMatchers.size() == 1)
      return cast(this.fMatchers.get(0)); 
    return CoreMatchers.allOf(castedMatchers());
  }
  
  private List<Matcher<? super Throwable>> castedMatchers() {
    return (List)new ArrayList<Matcher<?>>(this.fMatchers);
  }
  
  private Matcher<Throwable> cast(Matcher<?> singleMatcher) {
    return (Matcher)singleMatcher;
  }
}
