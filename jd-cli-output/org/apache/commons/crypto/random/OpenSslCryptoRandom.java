package org.apache.commons.crypto.random;

import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;
import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.Utils;

class OpenSslCryptoRandom extends Random implements CryptoRandom {
  private static final long serialVersionUID = -7828193502768789584L;
  
  private static final boolean nativeEnabled;
  
  private static final Throwable initException;
  
  static {
    boolean opensslLoaded = false;
    Throwable except = null;
    if (Crypto.isNativeCodeLoaded())
      try {
        OpenSslCryptoRandomNative.initSR();
        opensslLoaded = true;
      } catch (Exception t) {
        except = t;
      } catch (UnsatisfiedLinkError t) {
        except = t;
      }  
    nativeEnabled = opensslLoaded;
    initException = except;
  }
  
  public static boolean isNativeCodeEnabled() {
    return nativeEnabled;
  }
  
  public OpenSslCryptoRandom(Properties props) throws GeneralSecurityException {
    if (!nativeEnabled) {
      if (initException != null)
        throw new GeneralSecurityException("Native library could not be initialized", initException); 
      throw new GeneralSecurityException("Native library is not loaded");
    } 
    if (!OpenSslCryptoRandomNative.nextRandBytes(new byte[1]))
      throw new GeneralSecurityException("Check of nextRandBytes failed"); 
  }
  
  public void nextBytes(byte[] bytes) {
    if (!OpenSslCryptoRandomNative.nextRandBytes(bytes))
      throw new IllegalArgumentException("The nextRandBytes method failed"); 
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
  
  public void close() {}
}
