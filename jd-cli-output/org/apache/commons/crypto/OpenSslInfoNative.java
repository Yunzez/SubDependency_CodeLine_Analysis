package org.apache.commons.crypto;

class OpenSslInfoNative {
  public static final long VERSION_1_0_2X = 268443648L;
  
  public static final long VERSION_1_1_0X = 269484032L;
  
  public static native String NativeVersion();
  
  public static native String NativeName();
  
  public static native String NativeTimeStamp();
  
  public static native long OpenSSL();
  
  public static native String OpenSSLVersion(int paramInt);
}
