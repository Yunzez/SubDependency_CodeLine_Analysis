package org.junit.runners.model;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public class FrameworkField extends FrameworkMember<FrameworkField> {
  private final Field fField;
  
  FrameworkField(Field field) {
    this.fField = field;
  }
  
  public String getName() {
    return getField().getName();
  }
  
  public Annotation[] getAnnotations() {
    return this.fField.getAnnotations();
  }
  
  public boolean isPublic() {
    int modifiers = this.fField.getModifiers();
    return Modifier.isPublic(modifiers);
  }
  
  public boolean isShadowedBy(FrameworkField otherMember) {
    return otherMember.getName().equals(getName());
  }
  
  public boolean isStatic() {
    int modifiers = this.fField.getModifiers();
    return Modifier.isStatic(modifiers);
  }
  
  public Field getField() {
    return this.fField;
  }
  
  public Class<?> getType() {
    return this.fField.getType();
  }
  
  public Object get(Object target) throws IllegalArgumentException, IllegalAccessException {
    return this.fField.get(target);
  }
}
