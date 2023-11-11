package org.bouncycastle.util.test;

public final class NumberParsing {
  public static long decodeLongFromHex(String paramString) {
    return (paramString.charAt(1) == 'x' || paramString.charAt(1) == 'X') ? Long.parseLong(paramString.substring(2), 16) : Long.parseLong(paramString, 16);
  }
  
  public static int decodeIntFromHex(String paramString) {
    return (paramString.charAt(1) == 'x' || paramString.charAt(1) == 'X') ? Integer.parseInt(paramString.substring(2), 16) : Integer.parseInt(paramString, 16);
  }
}
