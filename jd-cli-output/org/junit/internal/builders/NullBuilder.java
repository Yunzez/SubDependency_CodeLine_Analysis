package org.junit.internal.builders;

import org.junit.runner.Runner;
import org.junit.runners.model.RunnerBuilder;

public class NullBuilder extends RunnerBuilder {
  public Runner runnerForClass(Class<?> each) throws Throwable {
    return null;
  }
}
