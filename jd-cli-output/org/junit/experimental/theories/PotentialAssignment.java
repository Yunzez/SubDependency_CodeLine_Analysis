package org.junit.experimental.theories;

public abstract class PotentialAssignment {
  public static class CouldNotGenerateValueException extends Exception {
    private static final long serialVersionUID = 1L;
  }
  
  public static PotentialAssignment forValue(final String name, final Object value) {
    return new PotentialAssignment() {
        public Object getValue() throws PotentialAssignment.CouldNotGenerateValueException {
          return value;
        }
        
        public String toString() {
          return String.format("[%s]", new Object[] { this.val$value });
        }
        
        public String getDescription() throws PotentialAssignment.CouldNotGenerateValueException {
          return name;
        }
      };
  }
  
  public abstract Object getValue() throws CouldNotGenerateValueException;
  
  public abstract String getDescription() throws CouldNotGenerateValueException;
}
