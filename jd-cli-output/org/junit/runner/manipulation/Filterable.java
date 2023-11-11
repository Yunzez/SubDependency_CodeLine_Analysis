package org.junit.runner.manipulation;

public interface Filterable {
  void filter(Filter paramFilter) throws NoTestsRemainException;
}
