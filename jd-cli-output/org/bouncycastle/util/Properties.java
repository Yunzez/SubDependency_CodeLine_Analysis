package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

public class Properties {
  private static final ThreadLocal threadProperties = new ThreadLocal();
  
  public static boolean isOverrideSet(String paramString) {
    try {
      return isSetTrue(getPropertyValue(paramString));
    } catch (AccessControlException accessControlException) {
      return false;
    } 
  }
  
  public static boolean isOverrideSetTo(String paramString, boolean paramBoolean) {
    try {
      String str = getPropertyValue(paramString);
      return paramBoolean ? isSetTrue(str) : isSetFalse(str);
    } catch (AccessControlException accessControlException) {
      return false;
    } 
  }
  
  public static boolean setThreadOverride(String paramString, boolean paramBoolean) {
    boolean bool = isOverrideSet(paramString);
    Map<Object, Object> map = threadProperties.get();
    if (map == null) {
      map = new HashMap<Object, Object>();
      threadProperties.set(map);
    } 
    map.put(paramString, paramBoolean ? "true" : "false");
    return bool;
  }
  
  public static boolean removeThreadOverride(String paramString) {
    Map map = threadProperties.get();
    if (map != null) {
      String str = (String)map.remove(paramString);
      if (str != null) {
        if (map.isEmpty())
          threadProperties.remove(); 
        return "true".equals(Strings.toLowerCase(str));
      } 
    } 
    return false;
  }
  
  public static BigInteger asBigInteger(String paramString) {
    String str = getPropertyValue(paramString);
    return (str != null) ? new BigInteger(str) : null;
  }
  
  public static Set<String> asKeySet(String paramString) {
    HashSet<String> hashSet = new HashSet();
    String str = getPropertyValue(paramString);
    if (str != null) {
      StringTokenizer stringTokenizer = new StringTokenizer(str, ",");
      while (stringTokenizer.hasMoreElements())
        hashSet.add(Strings.toLowerCase(stringTokenizer.nextToken()).trim()); 
    } 
    return Collections.unmodifiableSet(hashSet);
  }
  
  public static String getPropertyValue(final String propertyName) {
    String str = AccessController.<String>doPrivileged(new PrivilegedAction<String>() {
          public Object run() {
            return Security.getProperty(propertyName);
          }
        });
    if (str != null)
      return str; 
    Map map = threadProperties.get();
    if (map != null) {
      String str1 = (String)map.get(propertyName);
      if (str1 != null)
        return str1; 
    } 
    return AccessController.<String>doPrivileged(new PrivilegedAction<String>() {
          public Object run() {
            return System.getProperty(propertyName);
          }
        });
  }
  
  private static boolean isSetFalse(String paramString) {
    return (paramString == null || paramString.length() != 5) ? false : (((paramString.charAt(0) == 'f' || paramString.charAt(0) == 'F') && (paramString.charAt(1) == 'a' || paramString.charAt(1) == 'A') && (paramString.charAt(2) == 'l' || paramString.charAt(2) == 'L') && (paramString.charAt(3) == 's' || paramString.charAt(3) == 'S') && (paramString.charAt(4) == 'e' || paramString.charAt(4) == 'E')));
  }
  
  private static boolean isSetTrue(String paramString) {
    return (paramString == null || paramString.length() != 4) ? false : (((paramString.charAt(0) == 't' || paramString.charAt(0) == 'T') && (paramString.charAt(1) == 'r' || paramString.charAt(1) == 'R') && (paramString.charAt(2) == 'u' || paramString.charAt(2) == 'U') && (paramString.charAt(3) == 'e' || paramString.charAt(3) == 'E')));
  }
}
