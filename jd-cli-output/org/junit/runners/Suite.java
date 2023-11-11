package org.junit.runners;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import org.junit.internal.builders.AllDefaultPossibilitiesBuilder;
import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;

public class Suite extends ParentRunner<Runner> {
  private final List<Runner> fRunners;
  
  public static Runner emptySuite() {
    try {
      return new Suite((Class)null, new Class[0]);
    } catch (InitializationError e) {
      throw new RuntimeException("This shouldn't be possible");
    } 
  }
  
  private static Class<?>[] getAnnotatedClasses(Class<?> klass) throws InitializationError {
    SuiteClasses annotation = klass.<SuiteClasses>getAnnotation(SuiteClasses.class);
    if (annotation == null)
      throw new InitializationError(String.format("class '%s' must have a SuiteClasses annotation", new Object[] { klass.getName() })); 
    return annotation.value();
  }
  
  public Suite(Class<?> klass, RunnerBuilder builder) throws InitializationError {
    this(builder, klass, getAnnotatedClasses(klass));
  }
  
  public Suite(RunnerBuilder builder, Class<?>[] classes) throws InitializationError {
    this((Class<?>)null, builder.runners((Class<?>)null, classes));
  }
  
  protected Suite(Class<?> klass, Class<?>[] suiteClasses) throws InitializationError {
    this(new AllDefaultPossibilitiesBuilder(true), klass, suiteClasses);
  }
  
  protected Suite(RunnerBuilder builder, Class<?> klass, Class<?>[] suiteClasses) throws InitializationError {
    this(klass, builder.runners(klass, suiteClasses));
  }
  
  protected Suite(Class<?> klass, List<Runner> runners) throws InitializationError {
    super(klass);
    this.fRunners = runners;
  }
  
  protected List<Runner> getChildren() {
    return this.fRunners;
  }
  
  protected Description describeChild(Runner child) {
    return child.getDescription();
  }
  
  protected void runChild(Runner runner, RunNotifier notifier) {
    runner.run(notifier);
  }
  
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.TYPE})
  @Inherited
  public static @interface SuiteClasses {
    Class<?>[] value();
  }
}
