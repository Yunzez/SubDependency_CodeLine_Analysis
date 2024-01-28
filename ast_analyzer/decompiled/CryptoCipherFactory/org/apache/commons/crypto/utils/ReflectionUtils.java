package org.apache.commons.crypto.utils;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import org.apache.commons.crypto.cipher.CryptoCipher;

public final class ReflectionUtils {
  private static final Map<ClassLoader, Map<String, WeakReference<Class<?>>>> CACHE_CLASSES = new WeakHashMap<>();
  
  private static final ClassLoader CLASSLOADER;
  
  static {
    ClassLoader threadClassLoader = Thread.currentThread().getContextClassLoader();
    CLASSLOADER = (threadClassLoader != null) ? threadClassLoader : CryptoCipher.class.getClassLoader();
  }
  
  private static final Class<?> NEGATIVE_CACHE_SENTINEL = NegativeCacheSentinel.class;
  
  private static abstract class NegativeCacheSentinel {}
  
  public static <T> T newInstance(Class<T> klass, Object... args) {
    try {
      Constructor<T> ctor;
      if (args.length == 0) {
        ctor = klass.getDeclaredConstructor(new Class[0]);
      } else {
        Class<?>[] argClses = new Class[args.length];
        for (int i = 0; i < args.length; i++)
          argClses[i] = args[i].getClass(); 
        ctor = klass.getDeclaredConstructor(argClses);
      } 
      ctor.setAccessible(true);
      return ctor.newInstance(args);
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    } 
  }
  
  public static Class<?> getClassByName(String name) throws ClassNotFoundException {
    Class<?> ret = getClassByNameOrNull(name);
    if (ret == null)
      throw new ClassNotFoundException("Class " + name + " not found"); 
    return ret;
  }
  
  private static Class<?> getClassByNameOrNull(String name) {
    Map<String, WeakReference<Class<?>>> map;
    synchronized (CACHE_CLASSES) {
      map = CACHE_CLASSES.get(CLASSLOADER);
      if (map == null) {
        map = Collections.synchronizedMap(new WeakHashMap<>());
        CACHE_CLASSES.put(CLASSLOADER, map);
      } 
    } 
    Class<?> clazz = null;
    WeakReference<Class<?>> ref = map.get(name);
    if (ref != null)
      clazz = ref.get(); 
    if (clazz == null) {
      try {
        clazz = Class.forName(name, true, CLASSLOADER);
      } catch (ClassNotFoundException e) {
        map.put(name, new WeakReference<>(NEGATIVE_CACHE_SENTINEL));
        return null;
      } 
      map.put(name, new WeakReference<>(clazz));
      return clazz;
    } 
    if (clazz == NEGATIVE_CACHE_SENTINEL)
      return null; 
    return clazz;
  }
}
