package org.junit.runner.manipulation;

import org.junit.runner.Description;

public abstract class Filter {
  public static Filter ALL = new Filter() {
      public boolean shouldRun(Description description) {
        return true;
      }
      
      public String describe() {
        return "all tests";
      }
      
      public void apply(Object child) throws NoTestsRemainException {}
      
      public Filter intersect(Filter second) {
        return second;
      }
    };
  
  public static Filter matchMethodDescription(final Description desiredDescription) {
    return new Filter() {
        public boolean shouldRun(Description description) {
          if (description.isTest())
            return desiredDescription.equals(description); 
          for (Description each : description.getChildren()) {
            if (shouldRun(each))
              return true; 
          } 
          return false;
        }
        
        public String describe() {
          return String.format("Method %s", new Object[] { this.val$desiredDescription.getDisplayName() });
        }
      };
  }
  
  public abstract boolean shouldRun(Description paramDescription);
  
  public abstract String describe();
  
  public void apply(Object child) throws NoTestsRemainException {
    if (!(child instanceof Filterable))
      return; 
    Filterable filterable = (Filterable)child;
    filterable.filter(this);
  }
  
  public Filter intersect(final Filter second) {
    if (second == this || second == ALL)
      return this; 
    final Filter first = this;
    return new Filter() {
        public boolean shouldRun(Description description) {
          return (first.shouldRun(description) && second.shouldRun(description));
        }
        
        public String describe() {
          return first.describe() + " and " + second.describe();
        }
      };
  }
}
