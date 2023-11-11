package junit.framework;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import org.junit.internal.MethodSorter;

public class TestSuite implements Test {
  private String fName;
  
  public static Test createTest(Class<?> theClass, String name) {
    Constructor<?> constructor;
    Object test;
    try {
      constructor = getTestConstructor(theClass);
    } catch (NoSuchMethodException e) {
      return warning("Class " + theClass.getName() + " has no public constructor TestCase(String name) or TestCase()");
    } 
    try {
      if ((constructor.getParameterTypes()).length == 0) {
        test = constructor.newInstance(new Object[0]);
        if (test instanceof TestCase)
          ((TestCase)test).setName(name); 
      } else {
        test = constructor.newInstance(new Object[] { name });
      } 
    } catch (InstantiationException e) {
      return warning("Cannot instantiate test case: " + name + " (" + exceptionToString(e) + ")");
    } catch (InvocationTargetException e) {
      return warning("Exception in constructor: " + name + " (" + exceptionToString(e.getTargetException()) + ")");
    } catch (IllegalAccessException e) {
      return warning("Cannot access test case: " + name + " (" + exceptionToString(e) + ")");
    } 
    return (Test)test;
  }
  
  public static Constructor<?> getTestConstructor(Class<?> theClass) throws NoSuchMethodException {
    try {
      return theClass.getConstructor(new Class[] { String.class });
    } catch (NoSuchMethodException e) {
      return theClass.getConstructor(new Class[0]);
    } 
  }
  
  public static Test warning(final String message) {
    return new TestCase("warning") {
        protected void runTest() {
          fail(message);
        }
      };
  }
  
  private static String exceptionToString(Throwable t) {
    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    t.printStackTrace(writer);
    return stringWriter.toString();
  }
  
  private Vector<Test> fTests = new Vector<Test>(10);
  
  public TestSuite() {}
  
  public TestSuite(Class<?> theClass) {
    addTestsFromTestCase(theClass);
  }
  
  private void addTestsFromTestCase(Class<?> theClass) {
    this.fName = theClass.getName();
    try {
      getTestConstructor(theClass);
    } catch (NoSuchMethodException e) {
      addTest(warning("Class " + theClass.getName() + " has no public constructor TestCase(String name) or TestCase()"));
      return;
    } 
    if (!Modifier.isPublic(theClass.getModifiers())) {
      addTest(warning("Class " + theClass.getName() + " is not public"));
      return;
    } 
    Class<?> superClass = theClass;
    List<String> names = new ArrayList<String>();
    while (Test.class.isAssignableFrom(superClass)) {
      for (Method each : MethodSorter.getDeclaredMethods(superClass))
        addTestMethod(each, names, theClass); 
      superClass = superClass.getSuperclass();
    } 
    if (this.fTests.size() == 0)
      addTest(warning("No tests found in " + theClass.getName())); 
  }
  
  public TestSuite(Class<? extends TestCase> theClass, String name) {
    this(theClass);
    setName(name);
  }
  
  public TestSuite(String name) {
    setName(name);
  }
  
  public TestSuite(Class<?>... classes) {
    for (Class<?> each : classes)
      addTest(testCaseForClass(each)); 
  }
  
  private Test testCaseForClass(Class<?> each) {
    if (TestCase.class.isAssignableFrom(each))
      return new TestSuite(each.asSubclass(TestCase.class)); 
    return warning(each.getCanonicalName() + " does not extend TestCase");
  }
  
  public TestSuite(Class<? extends TestCase>[] classes, String name) {
    this((Class<?>[])classes);
    setName(name);
  }
  
  public void addTest(Test test) {
    this.fTests.add(test);
  }
  
  public void addTestSuite(Class<? extends TestCase> testClass) {
    addTest(new TestSuite(testClass));
  }
  
  public int countTestCases() {
    int count = 0;
    for (Test each : this.fTests)
      count += each.countTestCases(); 
    return count;
  }
  
  public String getName() {
    return this.fName;
  }
  
  public void run(TestResult result) {
    for (Test each : this.fTests) {
      if (result.shouldStop())
        break; 
      runTest(each, result);
    } 
  }
  
  public void runTest(Test test, TestResult result) {
    test.run(result);
  }
  
  public void setName(String name) {
    this.fName = name;
  }
  
  public Test testAt(int index) {
    return this.fTests.get(index);
  }
  
  public int testCount() {
    return this.fTests.size();
  }
  
  public Enumeration<Test> tests() {
    return this.fTests.elements();
  }
  
  public String toString() {
    if (getName() != null)
      return getName(); 
    return super.toString();
  }
  
  private void addTestMethod(Method m, List<String> names, Class<?> theClass) {
    String name = m.getName();
    if (names.contains(name))
      return; 
    if (!isPublicTestMethod(m)) {
      if (isTestMethod(m))
        addTest(warning("Test method isn't public: " + m.getName() + "(" + theClass.getCanonicalName() + ")")); 
      return;
    } 
    names.add(name);
    addTest(createTest(theClass, name));
  }
  
  private boolean isPublicTestMethod(Method m) {
    return (isTestMethod(m) && Modifier.isPublic(m.getModifiers()));
  }
  
  private boolean isTestMethod(Method m) {
    return ((m.getParameterTypes()).length == 0 && m.getName().startsWith("test") && m.getReturnType().equals(void.class));
  }
}
