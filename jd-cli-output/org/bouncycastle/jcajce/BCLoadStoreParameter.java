package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

public class BCLoadStoreParameter implements KeyStore.LoadStoreParameter {
  private final InputStream in;
  
  private final OutputStream out;
  
  private final KeyStore.ProtectionParameter protectionParameter;
  
  public BCLoadStoreParameter(OutputStream paramOutputStream, char[] paramArrayOfchar) {
    this(paramOutputStream, new KeyStore.PasswordProtection(paramArrayOfchar));
  }
  
  public BCLoadStoreParameter(InputStream paramInputStream, char[] paramArrayOfchar) {
    this(paramInputStream, new KeyStore.PasswordProtection(paramArrayOfchar));
  }
  
  public BCLoadStoreParameter(InputStream paramInputStream, KeyStore.ProtectionParameter paramProtectionParameter) {
    this(paramInputStream, null, paramProtectionParameter);
  }
  
  public BCLoadStoreParameter(OutputStream paramOutputStream, KeyStore.ProtectionParameter paramProtectionParameter) {
    this(null, paramOutputStream, paramProtectionParameter);
  }
  
  BCLoadStoreParameter(InputStream paramInputStream, OutputStream paramOutputStream, KeyStore.ProtectionParameter paramProtectionParameter) {
    this.in = paramInputStream;
    this.out = paramOutputStream;
    this.protectionParameter = paramProtectionParameter;
  }
  
  public KeyStore.ProtectionParameter getProtectionParameter() {
    return this.protectionParameter;
  }
  
  public OutputStream getOutputStream() {
    if (this.out == null)
      throw new UnsupportedOperationException("parameter not configured for storage - no OutputStream"); 
    return this.out;
  }
  
  public InputStream getInputStream() {
    if (this.out != null)
      throw new UnsupportedOperationException("parameter configured for storage OutputStream present"); 
    return this.in;
  }
}
