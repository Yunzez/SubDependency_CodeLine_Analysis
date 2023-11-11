package org.apache.commons.crypto.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.utils.Utils;

class OpenSslJnaCryptoRandom extends Random implements CryptoRandom {
  private static final long serialVersionUID = -7128193502768749585L;
  
  private final boolean rdrandEnabled;
  
  private transient PointerByReference rdrandEngine;
  
  public OpenSslJnaCryptoRandom(Properties props) throws GeneralSecurityException {
    if (!OpenSslJna.isEnabled())
      throw new GeneralSecurityException("Could not enable JNA access", OpenSslJna.initialisationError()); 
    boolean rdrandLoaded = false;
    try {
      OpenSslNativeJna.ENGINE_load_rdrand();
      this.rdrandEngine = OpenSslNativeJna.ENGINE_by_id("rdrand");
      int ENGINE_METHOD_RAND = 8;
      if (this.rdrandEngine != null) {
        int rc = OpenSslNativeJna.ENGINE_init(this.rdrandEngine);
        if (rc != 0) {
          int rc2 = OpenSslNativeJna.ENGINE_set_default(this.rdrandEngine, 8);
          if (rc2 != 0)
            rdrandLoaded = true; 
        } 
      } 
    } catch (Exception e) {
      throw new NoSuchAlgorithmException();
    } 
    this.rdrandEnabled = rdrandLoaded;
    if (!rdrandLoaded)
      closeRdrandEngine(); 
  }
  
  public void nextBytes(byte[] bytes) {
    synchronized (OpenSslJnaCryptoRandom.class) {
      if (this.rdrandEnabled && OpenSslNativeJna.RAND_get_rand_method().equals(OpenSslNativeJna.RAND_SSLeay())) {
        close();
        throw new IllegalStateException("rdrand should be used but default is detected");
      } 
      ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
      int retVal = OpenSslNativeJna.RAND_bytes(buf, bytes.length);
      throwOnError(retVal);
      buf.rewind();
      buf.get(bytes, 0, bytes.length);
    } 
  }
  
  public void setSeed(long seed) {}
  
  protected final int next(int numBits) {
    Utils.checkArgument((numBits >= 0 && numBits <= 32));
    int numBytes = (numBits + 7) / 8;
    byte[] b = new byte[numBytes];
    int next = 0;
    nextBytes(b);
    for (int i = 0; i < numBytes; i++)
      next = (next << 8) + (b[i] & 0xFF); 
    return next >>> numBytes * 8 - numBits;
  }
  
  public void close() {
    closeRdrandEngine();
    OpenSslNativeJna.ENGINE_cleanup();
  }
  
  private void closeRdrandEngine() {
    if (this.rdrandEngine != null) {
      OpenSslNativeJna.ENGINE_finish(this.rdrandEngine);
      OpenSslNativeJna.ENGINE_free(this.rdrandEngine);
    } 
  }
  
  public boolean isRdrandEnabled() {
    return this.rdrandEnabled;
  }
  
  private void throwOnError(int retVal) {
    if (retVal != 1) {
      NativeLong err = OpenSslNativeJna.ERR_peek_error();
      String errdesc = OpenSslNativeJna.ERR_error_string(err, null);
      close();
      throw new IllegalStateException("return code " + retVal + " from OpenSSL. Err code is " + err + ": " + errdesc);
    } 
  }
}
