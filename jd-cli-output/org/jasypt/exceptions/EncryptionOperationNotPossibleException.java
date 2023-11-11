package org.jasypt.exceptions;

public final class EncryptionOperationNotPossibleException extends RuntimeException {
  private static final long serialVersionUID = 6304674109588715145L;
  
  public EncryptionOperationNotPossibleException() {}
  
  public EncryptionOperationNotPossibleException(Throwable t) {
    super(t);
  }
  
  public EncryptionOperationNotPossibleException(String message) {
    super(message);
  }
}
