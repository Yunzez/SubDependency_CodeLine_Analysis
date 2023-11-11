package org.bouncycastle.pqc.crypto.qtesla;

public class QTESLASecurityCategory {
  public static final int PROVABLY_SECURE_I = 5;
  
  public static final int PROVABLY_SECURE_III = 6;
  
  static void validate(int paramInt) {
    switch (paramInt) {
      case 5:
      case 6:
        return;
    } 
    throw new IllegalArgumentException("unknown security category: " + paramInt);
  }
  
  static int getPrivateSize(int paramInt) {
    switch (paramInt) {
      case 5:
        return 5224;
      case 6:
        return 12392;
    } 
    throw new IllegalArgumentException("unknown security category: " + paramInt);
  }
  
  static int getPublicSize(int paramInt) {
    switch (paramInt) {
      case 5:
        return 14880;
      case 6:
        return 38432;
    } 
    throw new IllegalArgumentException("unknown security category: " + paramInt);
  }
  
  static int getSignatureSize(int paramInt) {
    switch (paramInt) {
      case 5:
        return 2592;
      case 6:
        return 5664;
    } 
    throw new IllegalArgumentException("unknown security category: " + paramInt);
  }
  
  public static String getName(int paramInt) {
    switch (paramInt) {
      case 5:
        return "qTESLA-p-I";
      case 6:
        return "qTESLA-p-III";
    } 
    throw new IllegalArgumentException("unknown security category: " + paramInt);
  }
}
