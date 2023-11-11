package org.jasypt.exceptions;

public final class EncryptionInitializationException extends RuntimeException {
  private static final long serialVersionUID = 8929638240023639778L;
  
  public EncryptionInitializationException() {}
  
  public EncryptionInitializationException(Throwable t) {
    super(t);
  }
  
  public EncryptionInitializationException(String msg, Throwable t) {
    super(msg, t);
  }
  
  public EncryptionInitializationException(String msg) {
    super(msg);
  }
}
