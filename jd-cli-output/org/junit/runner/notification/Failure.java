package org.junit.runner.notification;

import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import org.junit.runner.Description;

public class Failure implements Serializable {
  private static final long serialVersionUID = 1L;
  
  private final Description fDescription;
  
  private final Throwable fThrownException;
  
  public Failure(Description description, Throwable thrownException) {
    this.fThrownException = thrownException;
    this.fDescription = description;
  }
  
  public String getTestHeader() {
    return this.fDescription.getDisplayName();
  }
  
  public Description getDescription() {
    return this.fDescription;
  }
  
  public Throwable getException() {
    return this.fThrownException;
  }
  
  public String toString() {
    StringBuffer buffer = new StringBuffer();
    buffer.append(getTestHeader() + ": " + this.fThrownException.getMessage());
    return buffer.toString();
  }
  
  public String getTrace() {
    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    getException().printStackTrace(writer);
    StringBuffer buffer = stringWriter.getBuffer();
    return buffer.toString();
  }
  
  public String getMessage() {
    return getException().getMessage();
  }
}
