package org.junit.runners;

import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.internal.runners.model.ReflectiveCallable;
import org.junit.internal.runners.rules.RuleFieldValidator;
import org.junit.internal.runners.statements.ExpectException;
import org.junit.internal.runners.statements.Fail;
import org.junit.internal.runners.statements.FailOnTimeout;
import org.junit.internal.runners.statements.InvokeMethod;
import org.junit.internal.runners.statements.RunAfters;
import org.junit.internal.runners.statements.RunBefores;
import org.junit.rules.MethodRule;
import org.junit.rules.RunRules;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;

public class BlockJUnit4ClassRunner extends ParentRunner<FrameworkMethod> {
  public BlockJUnit4ClassRunner(Class<?> klass) throws InitializationError {
    super(klass);
  }
  
  protected void runChild(FrameworkMethod method, RunNotifier notifier) {
    Description description = describeChild(method);
    if (method.getAnnotation(Ignore.class) != null) {
      notifier.fireTestIgnored(description);
    } else {
      runLeaf(methodBlock(method), description, notifier);
    } 
  }
  
  protected Description describeChild(FrameworkMethod method) {
    return Description.createTestDescription(getTestClass().getJavaClass(), testName(method), method.getAnnotations());
  }
  
  protected List<FrameworkMethod> getChildren() {
    return computeTestMethods();
  }
  
  protected List<FrameworkMethod> computeTestMethods() {
    return getTestClass().getAnnotatedMethods((Class)Test.class);
  }
  
  protected void collectInitializationErrors(List<Throwable> errors) {
    super.collectInitializationErrors(errors);
    validateNoNonStaticInnerClass(errors);
    validateConstructor(errors);
    validateInstanceMethods(errors);
    validateFields(errors);
    validateMethods(errors);
  }
  
  protected void validateNoNonStaticInnerClass(List<Throwable> errors) {
    if (getTestClass().isANonStaticInnerClass()) {
      String gripe = "The inner class " + getTestClass().getName() + " is not static.";
      errors.add(new Exception(gripe));
    } 
  }
  
  protected void validateConstructor(List<Throwable> errors) {
    validateOnlyOneConstructor(errors);
    validateZeroArgConstructor(errors);
  }
  
  protected void validateOnlyOneConstructor(List<Throwable> errors) {
    if (!hasOneConstructor()) {
      String gripe = "Test class should have exactly one public constructor";
      errors.add(new Exception(gripe));
    } 
  }
  
  protected void validateZeroArgConstructor(List<Throwable> errors) {
    if (!getTestClass().isANonStaticInnerClass() && hasOneConstructor() && (getTestClass().getOnlyConstructor().getParameterTypes()).length != 0) {
      String gripe = "Test class should have exactly one public zero-argument constructor";
      errors.add(new Exception(gripe));
    } 
  }
  
  private boolean hasOneConstructor() {
    return ((getTestClass().getJavaClass().getConstructors()).length == 1);
  }
  
  @Deprecated
  protected void validateInstanceMethods(List<Throwable> errors) {
    validatePublicVoidNoArgMethods((Class)After.class, false, errors);
    validatePublicVoidNoArgMethods((Class)Before.class, false, errors);
    validateTestMethods(errors);
    if (computeTestMethods().size() == 0)
      errors.add(new Exception("No runnable methods")); 
  }
  
  protected void validateFields(List<Throwable> errors) {
    RuleFieldValidator.RULE_VALIDATOR.validate(getTestClass(), errors);
  }
  
  private void validateMethods(List<Throwable> errors) {
    RuleFieldValidator.RULE_METHOD_VALIDATOR.validate(getTestClass(), errors);
  }
  
  protected void validateTestMethods(List<Throwable> errors) {
    validatePublicVoidNoArgMethods((Class)Test.class, false, errors);
  }
  
  protected Object createTest() throws Exception {
    return getTestClass().getOnlyConstructor().newInstance(new Object[0]);
  }
  
  protected String testName(FrameworkMethod method) {
    return method.getName();
  }
  
  protected Statement methodBlock(FrameworkMethod method) {
    Object test;
    try {
      test = (new ReflectiveCallable() {
          protected Object runReflectiveCall() throws Throwable {
            return BlockJUnit4ClassRunner.this.createTest();
          }
        }).run();
    } catch (Throwable e) {
      return new Fail(e);
    } 
    Statement statement = methodInvoker(method, test);
    statement = possiblyExpectingExceptions(method, test, statement);
    statement = withPotentialTimeout(method, test, statement);
    statement = withBefores(method, test, statement);
    statement = withAfters(method, test, statement);
    statement = withRules(method, test, statement);
    return statement;
  }
  
  protected Statement methodInvoker(FrameworkMethod method, Object test) {
    return new InvokeMethod(method, test);
  }
  
  @Deprecated
  protected Statement possiblyExpectingExceptions(FrameworkMethod method, Object test, Statement next) {
    Test annotation = method.<Test>getAnnotation(Test.class);
    return expectsException(annotation) ? new ExpectException(next, getExpectedException(annotation)) : next;
  }
  
  @Deprecated
  protected Statement withPotentialTimeout(FrameworkMethod method, Object test, Statement next) {
    long timeout = getTimeout(method.<Test>getAnnotation(Test.class));
    return (timeout > 0L) ? new FailOnTimeout(next, timeout) : next;
  }
  
  @Deprecated
  protected Statement withBefores(FrameworkMethod method, Object target, Statement statement) {
    List<FrameworkMethod> befores = getTestClass().getAnnotatedMethods((Class)Before.class);
    return befores.isEmpty() ? statement : new RunBefores(statement, befores, target);
  }
  
  @Deprecated
  protected Statement withAfters(FrameworkMethod method, Object target, Statement statement) {
    List<FrameworkMethod> afters = getTestClass().getAnnotatedMethods((Class)After.class);
    return afters.isEmpty() ? statement : new RunAfters(statement, afters, target);
  }
  
  private Statement withRules(FrameworkMethod method, Object target, Statement statement) {
    List<TestRule> testRules = getTestRules(target);
    Statement result = statement;
    result = withMethodRules(method, testRules, target, result);
    result = withTestRules(method, testRules, result);
    return result;
  }
  
  private Statement withMethodRules(FrameworkMethod method, List<TestRule> testRules, Object target, Statement result) {
    for (MethodRule each : getMethodRules(target)) {
      if (!testRules.contains(each))
        result = each.apply(result, method, target); 
    } 
    return result;
  }
  
  private List<MethodRule> getMethodRules(Object target) {
    return rules(target);
  }
  
  protected List<MethodRule> rules(Object target) {
    return getTestClass().getAnnotatedFieldValues(target, (Class)Rule.class, MethodRule.class);
  }
  
  private Statement withTestRules(FrameworkMethod method, List<TestRule> testRules, Statement statement) {
    return testRules.isEmpty() ? statement : new RunRules(statement, testRules, describeChild(method));
  }
  
  protected List<TestRule> getTestRules(Object target) {
    List<TestRule> result = getTestClass().getAnnotatedMethodValues(target, (Class)Rule.class, TestRule.class);
    result.addAll(getTestClass().getAnnotatedFieldValues(target, (Class)Rule.class, TestRule.class));
    return result;
  }
  
  private Class<? extends Throwable> getExpectedException(Test annotation) {
    if (annotation == null || annotation.expected() == Test.None.class)
      return null; 
    return annotation.expected();
  }
  
  private boolean expectsException(Test annotation) {
    return (getExpectedException(annotation) != null);
  }
  
  private long getTimeout(Test annotation) {
    if (annotation == null)
      return 0L; 
    return annotation.timeout();
  }
}
