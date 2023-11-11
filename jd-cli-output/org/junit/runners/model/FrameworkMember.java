package org.junit.runners.model;

import java.lang.annotation.Annotation;
import java.util.List;

public abstract class FrameworkMember<T extends FrameworkMember<T>> {
  abstract Annotation[] getAnnotations();
  
  abstract boolean isShadowedBy(T paramT);
  
  boolean isShadowedBy(List<T> members) {
    for (FrameworkMember frameworkMember : members) {
      if (isShadowedBy((T)frameworkMember))
        return true; 
    } 
    return false;
  }
  
  public abstract boolean isPublic();
  
  public abstract boolean isStatic();
  
  public abstract String getName();
  
  public abstract Class<?> getType();
}
