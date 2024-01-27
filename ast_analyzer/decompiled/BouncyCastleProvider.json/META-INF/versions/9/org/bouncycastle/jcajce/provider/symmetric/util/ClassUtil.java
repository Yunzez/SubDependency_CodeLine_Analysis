package META-INF.versions.9.org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class ClassUtil {
  public static Class loadClass(Class paramClass, String paramString) {
    try {
      ClassLoader classLoader = paramClass.getClassLoader();
      if (classLoader != null)
        return classLoader.loadClass(paramString); 
      return AccessController.<Class<?>>doPrivileged((PrivilegedAction<Class<?>>)new Object(paramString));
    } catch (ClassNotFoundException classNotFoundException) {
      return null;
    } 
  }
}
