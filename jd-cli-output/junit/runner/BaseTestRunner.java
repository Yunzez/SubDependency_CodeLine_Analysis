package junit.runner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.text.NumberFormat;
import java.util.Properties;
import junit.framework.AssertionFailedError;
import junit.framework.Test;
import junit.framework.TestListener;
import junit.framework.TestSuite;

public abstract class BaseTestRunner implements TestListener {
  public static final String SUITE_METHODNAME = "suite";
  
  private static Properties fPreferences;
  
  static int fgMaxMessageLength = 500;
  
  static boolean fgFilterStack = true;
  
  boolean fLoading = true;
  
  public synchronized void startTest(Test test) {
    testStarted(test.toString());
  }
  
  protected static void setPreferences(Properties preferences) {
    fPreferences = preferences;
  }
  
  protected static Properties getPreferences() {
    if (fPreferences == null) {
      fPreferences = new Properties();
      fPreferences.put("loading", "true");
      fPreferences.put("filterstack", "true");
      readPreferences();
    } 
    return fPreferences;
  }
  
  public static void savePreferences() throws IOException {
    FileOutputStream fos = new FileOutputStream(getPreferencesFile());
    try {
      getPreferences().store(fos, "");
    } finally {
      fos.close();
    } 
  }
  
  public static void setPreference(String key, String value) {
    getPreferences().put(key, value);
  }
  
  public synchronized void endTest(Test test) {
    testEnded(test.toString());
  }
  
  public synchronized void addError(Test test, Throwable t) {
    testFailed(1, test, t);
  }
  
  public synchronized void addFailure(Test test, AssertionFailedError t) {
    testFailed(2, test, t);
  }
  
  public abstract void testStarted(String paramString);
  
  public abstract void testEnded(String paramString);
  
  public abstract void testFailed(int paramInt, Test paramTest, Throwable paramThrowable);
  
  public Test getTest(String suiteClassName) {
    if (suiteClassName.length() <= 0) {
      clearStatus();
      return null;
    } 
    Class<?> testClass = null;
    try {
      testClass = loadSuiteClass(suiteClassName);
    } catch (ClassNotFoundException e) {
      String clazz = e.getMessage();
      if (clazz == null)
        clazz = suiteClassName; 
      runFailed("Class not found \"" + clazz + "\"");
      return null;
    } catch (Exception e) {
      runFailed("Error: " + e.toString());
      return null;
    } 
    Method suiteMethod = null;
    try {
      suiteMethod = testClass.getMethod("suite", new Class[0]);
    } catch (Exception e) {
      clearStatus();
      return new TestSuite(testClass);
    } 
    if (!Modifier.isStatic(suiteMethod.getModifiers())) {
      runFailed("Suite() method must be static");
      return null;
    } 
    Test test = null;
    try {
      test = (Test)suiteMethod.invoke(null, (Object[])new Class[0]);
      if (test == null)
        return test; 
    } catch (InvocationTargetException e) {
      runFailed("Failed to invoke suite():" + e.getTargetException().toString());
      return null;
    } catch (IllegalAccessException e) {
      runFailed("Failed to invoke suite():" + e.toString());
      return null;
    } 
    clearStatus();
    return test;
  }
  
  public String elapsedTimeAsString(long runTime) {
    return NumberFormat.getInstance().format(runTime / 1000.0D);
  }
  
  protected String processArguments(String[] args) {
    String suiteName = null;
    for (int i = 0; i < args.length; i++) {
      if (args[i].equals("-noloading")) {
        setLoading(false);
      } else if (args[i].equals("-nofilterstack")) {
        fgFilterStack = false;
      } else if (args[i].equals("-c")) {
        if (args.length > i + 1) {
          suiteName = extractClassName(args[i + 1]);
        } else {
          System.out.println("Missing Test class name");
        } 
        i++;
      } else {
        suiteName = args[i];
      } 
    } 
    return suiteName;
  }
  
  public void setLoading(boolean enable) {
    this.fLoading = enable;
  }
  
  public String extractClassName(String className) {
    if (className.startsWith("Default package for"))
      return className.substring(className.lastIndexOf(".") + 1); 
    return className;
  }
  
  public static String truncate(String s) {
    if (fgMaxMessageLength != -1 && s.length() > fgMaxMessageLength)
      s = s.substring(0, fgMaxMessageLength) + "..."; 
    return s;
  }
  
  protected abstract void runFailed(String paramString);
  
  protected Class<?> loadSuiteClass(String suiteClassName) throws ClassNotFoundException {
    return Class.forName(suiteClassName);
  }
  
  protected void clearStatus() {}
  
  protected boolean useReloadingTestSuiteLoader() {
    return (getPreference("loading").equals("true") && this.fLoading);
  }
  
  private static File getPreferencesFile() {
    String home = System.getProperty("user.home");
    return new File(home, "junit.properties");
  }
  
  private static void readPreferences() {
    InputStream is = null;
    try {
      is = new FileInputStream(getPreferencesFile());
      setPreferences(new Properties(getPreferences()));
      getPreferences().load(is);
    } catch (IOException e) {
      try {
        if (is != null)
          is.close(); 
      } catch (IOException e1) {}
    } 
  }
  
  public static String getPreference(String key) {
    return getPreferences().getProperty(key);
  }
  
  public static int getPreference(String key, int dflt) {
    String value = getPreference(key);
    int intValue = dflt;
    if (value == null)
      return intValue; 
    try {
      intValue = Integer.parseInt(value);
    } catch (NumberFormatException ne) {}
    return intValue;
  }
  
  public static String getFilteredTrace(Throwable t) {
    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    t.printStackTrace(writer);
    StringBuffer buffer = stringWriter.getBuffer();
    String trace = buffer.toString();
    return getFilteredTrace(trace);
  }
  
  public static String getFilteredTrace(String stack) {
    if (showStackRaw())
      return stack; 
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    StringReader sr = new StringReader(stack);
    BufferedReader br = new BufferedReader(sr);
    try {
      String line;
      while ((line = br.readLine()) != null) {
        if (!filterLine(line))
          pw.println(line); 
      } 
    } catch (Exception IOException) {
      return stack;
    } 
    return sw.toString();
  }
  
  protected static boolean showStackRaw() {
    return (!getPreference("filterstack").equals("true") || !fgFilterStack);
  }
  
  static boolean filterLine(String line) {
    String[] patterns = { "junit.framework.TestCase", "junit.framework.TestResult", "junit.framework.TestSuite", "junit.framework.Assert.", "junit.swingui.TestRunner", "junit.awtui.TestRunner", "junit.textui.TestRunner", "java.lang.reflect.Method.invoke(" };
    for (int i = 0; i < patterns.length; i++) {
      if (line.indexOf(patterns[i]) > 0)
        return true; 
    } 
    return false;
  }
  
  static {
    fgMaxMessageLength = getPreference("maxmessage", fgMaxMessageLength);
  }
}
