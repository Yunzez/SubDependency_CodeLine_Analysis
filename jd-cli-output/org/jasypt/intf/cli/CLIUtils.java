package org.jasypt.intf.cli;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.jasypt.commons.CommonUtils;

final class CLIUtils {
  static void showEnvironment(boolean verbose) {
    if (verbose) {
      System.out.println("\n----ENVIRONMENT-----------------\n");
      System.out.println("Runtime: " + 
          System.getProperty("java.vm.vendor") + " " + 
          System.getProperty("java.vm.name") + " " + 
          System.getProperty("java.vm.version") + " ");
      System.out.println("\n");
    } 
  }
  
  static void showArgumentDescription(Properties argumentValues, boolean verbose) {
    if (verbose) {
      System.out.println("\n----ARGUMENTS-------------------\n");
      Iterator<Map.Entry<Object, Object>> entriesIter = argumentValues.entrySet().iterator();
      while (entriesIter.hasNext()) {
        Map.Entry entry = entriesIter.next();
        System.out.println((new StringBuilder())
            .append(entry.getKey()).append(": ").append(entry.getValue()).toString());
      } 
      System.out.println("\n");
    } 
  }
  
  static void showOutput(String output, boolean verbose) {
    if (verbose) {
      System.out.println("\n----OUTPUT----------------------\n");
      System.out.println(output);
      System.out.println("\n");
    } else {
      System.out.println(output);
    } 
  }
  
  static void showError(Throwable t, boolean verbose) {
    if (verbose) {
      System.err.println("\n----ERROR-----------------------\n");
      if (t instanceof org.jasypt.exceptions.EncryptionOperationNotPossibleException) {
        System.err.println("Operation not possible (Bad input or parameters)");
      } else if (t.getMessage() != null) {
        System.err.println(t.getMessage());
      } else {
        System.err.println(t.getClass().getName());
      } 
      System.err.println("\n");
    } else {
      System.err.print("ERROR: ");
      if (t instanceof org.jasypt.exceptions.EncryptionOperationNotPossibleException) {
        System.err.println("Operation not possible (Bad input or parameters)");
      } else if (t.getMessage() != null) {
        System.err.println(t.getMessage());
      } else {
        System.err.println(t.getClass().getName());
      } 
    } 
  }
  
  static boolean getVerbosity(String[] args) {
    for (int i = 0; i < args.length; i++) {
      String key = CommonUtils.substringBefore(args[i], "=");
      String value = CommonUtils.substringAfter(args[i], "=");
      if (!CommonUtils.isEmpty(key) && !CommonUtils.isEmpty(value))
        if ("verbose".equals(key)) {
          Boolean verbosity = CommonUtils.getStandardBooleanValue(value);
          return (verbosity != null) ? verbosity.booleanValue() : false;
        }  
    } 
    return true;
  }
  
  static Properties getArgumentValues(String appName, String[] args, String[][] requiredArgNames, String[][] optionalArgNames) {
    Set argNames = new HashSet();
    int i;
    for (i = 0; i < requiredArgNames.length; i++)
      argNames.addAll(Arrays.asList(requiredArgNames[i])); 
    for (i = 0; i < optionalArgNames.length; i++)
      argNames.addAll(Arrays.asList(optionalArgNames[i])); 
    Properties argumentValues = new Properties();
    int j;
    for (j = 0; j < args.length; j++) {
      String key = CommonUtils.substringBefore(args[j], "=");
      String value = CommonUtils.substringAfter(args[j], "=");
      if (CommonUtils.isEmpty(key) || CommonUtils.isEmpty(value))
        throw new IllegalArgumentException("Bad argument: " + args[j]); 
      if (argNames.contains(key)) {
        if (value.startsWith("\"") && value.endsWith("\"")) {
          argumentValues.setProperty(key, value
              
              .substring(1, value.length() - 1));
        } else {
          argumentValues.setProperty(key, value);
        } 
      } else {
        throw new IllegalArgumentException("Bad argument: " + args[j]);
      } 
    } 
    for (j = 0; j < requiredArgNames.length; j++) {
      boolean found = false;
      for (int k = 0; k < (requiredArgNames[j]).length; k++) {
        if (argumentValues.containsKey(requiredArgNames[j][k]))
          found = true; 
      } 
      if (!found)
        showUsageAndExit(appName, requiredArgNames, optionalArgNames); 
    } 
    return argumentValues;
  }
  
  static void showUsageAndExit(String appName, String[][] requiredArgNames, String[][] optionalArgNames) {
    System.err.println("\nUSAGE: " + appName + " [ARGUMENTS]\n");
    System.err.println("  * Arguments must apply to format:\n");
    System.err.println("      \"arg1=value1 arg2=value2 arg3=value3 ...\"");
    System.err.println();
    System.err.println("  * Required arguments:\n");
    int i;
    for (i = 0; i < requiredArgNames.length; i++) {
      System.err.print("      ");
      if ((requiredArgNames[i]).length == 1) {
        System.err.print(requiredArgNames[i][0]);
      } else {
        System.err.print("(");
        for (int j = 0; j < (requiredArgNames[i]).length; j++) {
          if (j > 0)
            System.err.print(" | "); 
          System.err.print(requiredArgNames[i][j]);
        } 
        System.err.print(")");
      } 
      System.err.println();
    } 
    System.err.println();
    System.err.println("  * Optional arguments:\n");
    for (i = 0; i < optionalArgNames.length; i++) {
      System.err.print("      ");
      if ((optionalArgNames[i]).length == 1) {
        System.err.print(optionalArgNames[i][0]);
      } else {
        System.err.print("(");
        for (int j = 0; j < (optionalArgNames[i]).length; j++) {
          if (j > 0)
            System.err.print(" | "); 
          System.err.print(optionalArgNames[i][j]);
        } 
        System.err.print(")");
      } 
      System.err.println();
    } 
    System.exit(1);
  }
}
