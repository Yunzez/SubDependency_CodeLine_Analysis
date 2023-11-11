package org.apache.commons.crypto.random;

class OpenSslCryptoRandomNative {
  public static native void initSR();
  
  public static native boolean nextRandBytes(byte[] paramArrayOfbyte);
}
