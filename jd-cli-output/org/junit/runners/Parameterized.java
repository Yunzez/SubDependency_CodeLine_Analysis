package org.junit.runners;

import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.FrameworkField;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;

public class Parameterized extends Suite {
  private class TestClassRunnerForParameters extends BlockJUnit4ClassRunner {
    private final Object[] fParameters;
    
    private final String fName;
    
    TestClassRunnerForParameters(Class<?> type, Object[] parameters, String name) throws InitializationError {
      super(type);
      this.fParameters = parameters;
      this.fName = name;
    }
    
    public Object createTest() throws Exception {
      if (Parameterized.this.fieldsAreAnnotated())
        return createTestUsingFieldInjection(); 
      return createTestUsingConstructorInjection();
    }
    
    private Object createTestUsingConstructorInjection() throws Exception {
      return getTestClass().getOnlyConstructor().newInstance(this.fParameters);
    }
    
    private Object createTestUsingFieldInjection() throws Exception {
      List<FrameworkField> annotatedFieldsByParameter = Parameterized.this.getAnnotatedFieldsByParameter();
      if (annotatedFieldsByParameter.size() != this.fParameters.length)
        throw new Exception("Wrong number of parameters and @Parameter fields. @Parameter fields counted: " + annotatedFieldsByParameter.size() + ", available parameters: " + this.fParameters.length + "."); 
      Object testClassInstance = getTestClass().getJavaClass().newInstance();
      for (FrameworkField each : annotatedFieldsByParameter) {
        Field field = each.getField();
        Parameterized.Parameter annotation = field.<Parameterized.Parameter>getAnnotation(Parameterized.Parameter.class);
        int index = annotation.value();
        try {
          field.set(testClassInstance, this.fParameters[index]);
        } catch (IllegalArgumentException iare) {
          throw new Exception(getTestClass().getName() + ": Trying to set " + field.getName() + " with the value " + this.fParameters[index] + " that is not the right type (" + this.fParameters[index].getClass().getSimpleName() + " instead of " + field.getType().getSimpleName() + ").", iare);
        } 
      } 
      return testClassInstance;
    }
    
    protected String getName() {
      return this.fName;
    }
    
    protected String testName(FrameworkMethod method) {
      return method.getName() + getName();
    }
    
    protected void validateConstructor(List<Throwable> errors) {
      validateOnlyOneConstructor(errors);
      if (Parameterized.this.fieldsAreAnnotated())
        validateZeroArgConstructor(errors); 
    }
    
    protected void validateFields(List<Throwable> errors) {
      super.validateFields(errors);
      if (Parameterized.this.fieldsAreAnnotated()) {
        List<FrameworkField> annotatedFieldsByParameter = Parameterized.this.getAnnotatedFieldsByParameter();
        int[] usedIndices = new int[annotatedFieldsByParameter.size()];
        for (FrameworkField each : annotatedFieldsByParameter) {
          int i = ((Parameterized.Parameter)each.getField().<Parameterized.Parameter>getAnnotation(Parameterized.Parameter.class)).value();
          if (i < 0 || i > annotatedFieldsByParameter.size() - 1) {
            errors.add(new Exception("Invalid @Parameter value: " + i + ". @Parameter fields counted: " + annotatedFieldsByParameter.size() + ". Please use an index between 0 and " + (annotatedFieldsByParameter.size() - 1) + "."));
            continue;
          } 
          usedIndices[i] = usedIndices[i] + 1;
        } 
        for (int index = 0; index < usedIndices.length; index++) {
          int numberOfUse = usedIndices[index];
          if (numberOfUse == 0) {
            errors.add(new Exception("@Parameter(" + index + ") is never used."));
          } else if (numberOfUse > 1) {
            errors.add(new Exception("@Parameter(" + index + ") is used more than once (" + numberOfUse + ")."));
          } 
        } 
      } 
    }
    
    protected Statement classBlock(RunNotifier notifier) {
      return childrenInvoker(notifier);
    }
    
    protected Annotation[] getRunnerAnnotations() {
      return new Annotation[0];
    }
  }
  
  private static final List<Runner> NO_RUNNERS = Collections.emptyList();
  
  private final ArrayList<Runner> runners = new ArrayList<Runner>();
  
  public Parameterized(Class<?> klass) throws Throwable {
    super(klass, NO_RUNNERS);
    Parameters parameters = getParametersMethod().<Parameters>getAnnotation(Parameters.class);
    createRunnersForParameters(allParameters(), parameters.name());
  }
  
  protected List<Runner> getChildren() {
    return this.runners;
  }
  
  private Iterable<Object[]> allParameters() throws Throwable {
    Object parameters = getParametersMethod().invokeExplosively(null, new Object[0]);
    if (parameters instanceof Iterable)
      return (Iterable<Object[]>)parameters; 
    throw parametersMethodReturnedWrongType();
  }
  
  private FrameworkMethod getParametersMethod() throws Exception {
    List<FrameworkMethod> methods = getTestClass().getAnnotatedMethods((Class)Parameters.class);
    for (FrameworkMethod each : methods) {
      if (each.isStatic() && each.isPublic())
        return each; 
    } 
    throw new Exception("No public static parameters method on class " + getTestClass().getName());
  }
  
  private void createRunnersForParameters(Iterable<Object[]> allParameters, String namePattern) throws InitializationError, Exception {
    try {
      int i = 0;
      for (Object[] parametersOfSingleTest : allParameters) {
        String name = nameFor(namePattern, i, parametersOfSingleTest);
        TestClassRunnerForParameters runner = new TestClassRunnerForParameters(getTestClass().getJavaClass(), parametersOfSingleTest, name);
        this.runners.add(runner);
        i++;
      } 
    } catch (ClassCastException e) {
      throw parametersMethodReturnedWrongType();
    } 
  }
  
  private String nameFor(String namePattern, int index, Object[] parameters) {
    String finalPattern = namePattern.replaceAll("\\{index\\}", Integer.toString(index));
    String name = MessageFormat.format(finalPattern, parameters);
    return "[" + name + "]";
  }
  
  private Exception parametersMethodReturnedWrongType() throws Exception {
    String className = getTestClass().getName();
    String methodName = getParametersMethod().getName();
    String message = MessageFormat.format("{0}.{1}() must return an Iterable of arrays.", new Object[] { className, methodName });
    return new Exception(message);
  }
  
  private List<FrameworkField> getAnnotatedFieldsByParameter() {
    return getTestClass().getAnnotatedFields((Class)Parameter.class);
  }
  
  private boolean fieldsAreAnnotated() {
    return !getAnnotatedFieldsByParameter().isEmpty();
  }
  
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.FIELD})
  public static @interface Parameter {
    int value() default 0;
  }
  
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD})
  public static @interface Parameters {
    String name() default "{index}";
  }
}
