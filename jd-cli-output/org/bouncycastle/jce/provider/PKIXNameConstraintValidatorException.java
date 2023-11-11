package org.bouncycastle.jce.provider;

public class PKIXNameConstraintValidatorException extends Exception {
  private Throwable cause;
  
  public PKIXNameConstraintValidatorException(String paramString) {
    super(paramString);
  }
  
  public PKIXNameConstraintValidatorException(String paramString, Throwable paramThrowable) {
    super(paramString);
    this.cause = paramThrowable;
  }
  
  public Throwable getCause() {
    return this.cause;
  }
}
