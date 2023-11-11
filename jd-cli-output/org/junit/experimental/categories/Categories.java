package org.junit.experimental.categories;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.runner.Description;
import org.junit.runner.manipulation.Filter;
import org.junit.runner.manipulation.NoTestsRemainException;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;

public class Categories extends Suite {
  public static class CategoryFilter extends Filter {
    private final Class<?> fIncluded;
    
    private final Class<?> fExcluded;
    
    public static CategoryFilter include(Class<?> categoryType) {
      return new CategoryFilter(categoryType, null);
    }
    
    public CategoryFilter(Class<?> includedCategory, Class<?> excludedCategory) {
      this.fIncluded = includedCategory;
      this.fExcluded = excludedCategory;
    }
    
    public String describe() {
      return "category " + this.fIncluded;
    }
    
    public boolean shouldRun(Description description) {
      if (hasCorrectCategoryAnnotation(description))
        return true; 
      for (Description each : description.getChildren()) {
        if (shouldRun(each))
          return true; 
      } 
      return false;
    }
    
    private boolean hasCorrectCategoryAnnotation(Description description) {
      List<Class<?>> categories = categories(description);
      if (categories.isEmpty())
        return (this.fIncluded == null); 
      for (Class<?> each : categories) {
        if (this.fExcluded != null && this.fExcluded.isAssignableFrom(each))
          return false; 
      } 
      for (Class<?> each : categories) {
        if (this.fIncluded == null || this.fIncluded.isAssignableFrom(each))
          return true; 
      } 
      return false;
    }
    
    private List<Class<?>> categories(Description description) {
      ArrayList<Class<?>> categories = new ArrayList<Class<?>>();
      categories.addAll(Arrays.asList(directCategories(description)));
      categories.addAll(Arrays.asList(directCategories(parentDescription(description))));
      return categories;
    }
    
    private Description parentDescription(Description description) {
      Class<?> testClass = description.getTestClass();
      if (testClass == null)
        return null; 
      return Description.createSuiteDescription(testClass);
    }
    
    private Class<?>[] directCategories(Description description) {
      if (description == null)
        return new Class[0]; 
      Category annotation = description.<Category>getAnnotation(Category.class);
      if (annotation == null)
        return new Class[0]; 
      return annotation.value();
    }
  }
  
  public Categories(Class<?> klass, RunnerBuilder builder) throws InitializationError {
    super(klass, builder);
    try {
      filter(new CategoryFilter(getIncludedCategory(klass), getExcludedCategory(klass)));
    } catch (NoTestsRemainException e) {
      throw new InitializationError(e);
    } 
    assertNoCategorizedDescendentsOfUncategorizeableParents(getDescription());
  }
  
  private Class<?> getIncludedCategory(Class<?> klass) {
    IncludeCategory annotation = klass.<IncludeCategory>getAnnotation(IncludeCategory.class);
    return (annotation == null) ? null : annotation.value();
  }
  
  private Class<?> getExcludedCategory(Class<?> klass) {
    ExcludeCategory annotation = klass.<ExcludeCategory>getAnnotation(ExcludeCategory.class);
    return (annotation == null) ? null : annotation.value();
  }
  
  private void assertNoCategorizedDescendentsOfUncategorizeableParents(Description description) throws InitializationError {
    if (!canHaveCategorizedChildren(description))
      assertNoDescendantsHaveCategoryAnnotations(description); 
    for (Description each : description.getChildren())
      assertNoCategorizedDescendentsOfUncategorizeableParents(each); 
  }
  
  private void assertNoDescendantsHaveCategoryAnnotations(Description description) throws InitializationError {
    for (Description each : description.getChildren()) {
      if (each.getAnnotation(Category.class) != null)
        throw new InitializationError("Category annotations on Parameterized classes are not supported on individual methods."); 
      assertNoDescendantsHaveCategoryAnnotations(each);
    } 
  }
  
  private static boolean canHaveCategorizedChildren(Description description) {
    for (Description each : description.getChildren()) {
      if (each.getTestClass() == null)
        return false; 
    } 
    return true;
  }
  
  @Retention(RetentionPolicy.RUNTIME)
  public static @interface ExcludeCategory {
    Class<?> value();
  }
  
  @Retention(RetentionPolicy.RUNTIME)
  public static @interface IncludeCategory {
    Class<?> value();
  }
}
