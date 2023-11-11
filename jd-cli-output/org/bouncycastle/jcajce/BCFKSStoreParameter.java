package org.bouncycastle.jcajce;

import java.io.OutputStream;
import java.security.KeyStore;
import org.bouncycastle.crypto.util.PBKDFConfig;

public class BCFKSStoreParameter implements KeyStore.LoadStoreParameter {
  private final KeyStore.ProtectionParameter protectionParameter;
  
  private final PBKDFConfig storeConfig;
  
  private OutputStream out;
  
  public BCFKSStoreParameter(OutputStream paramOutputStream, PBKDFConfig paramPBKDFConfig, char[] paramArrayOfchar) {
    this(paramOutputStream, paramPBKDFConfig, new KeyStore.PasswordProtection(paramArrayOfchar));
  }
  
  public BCFKSStoreParameter(OutputStream paramOutputStream, PBKDFConfig paramPBKDFConfig, KeyStore.ProtectionParameter paramProtectionParameter) {
    this.out = paramOutputStream;
    this.storeConfig = paramPBKDFConfig;
    this.protectionParameter = paramProtectionParameter;
  }
  
  public KeyStore.ProtectionParameter getProtectionParameter() {
    return this.protectionParameter;
  }
  
  public OutputStream getOutputStream() {
    return this.out;
  }
  
  public PBKDFConfig getStorePBKDFConfig() {
    return this.storeConfig;
  }
}
