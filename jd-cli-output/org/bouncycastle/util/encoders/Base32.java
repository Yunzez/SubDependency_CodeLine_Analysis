package org.bouncycastle.util.encoders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.util.Strings;

public class Base32 {
  private static final Encoder encoder = new Base32Encoder();
  
  public static String toBase32String(byte[] paramArrayOfbyte) {
    return toBase32String(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  public static String toBase32String(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = encode(paramArrayOfbyte, paramInt1, paramInt2);
    return Strings.fromByteArray(arrayOfByte);
  }
  
  public static byte[] encode(byte[] paramArrayOfbyte) {
    return encode(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  public static byte[] encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = encoder.getEncodedLength(paramInt2);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(i);
    try {
      encoder.encode(paramArrayOfbyte, paramInt1, paramInt2, byteArrayOutputStream);
    } catch (Exception exception) {
      throw new EncoderException("exception encoding base32 string: " + exception.getMessage(), exception);
    } 
    return byteArrayOutputStream.toByteArray();
  }
  
  public static int encode(byte[] paramArrayOfbyte, OutputStream paramOutputStream) throws IOException {
    return encoder.encode(paramArrayOfbyte, 0, paramArrayOfbyte.length, paramOutputStream);
  }
  
  public static int encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    return encoder.encode(paramArrayOfbyte, paramInt1, paramInt2, paramOutputStream);
  }
  
  public static byte[] decode(byte[] paramArrayOfbyte) {
    int i = paramArrayOfbyte.length / 8 * 5;
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(i);
    try {
      encoder.decode(paramArrayOfbyte, 0, paramArrayOfbyte.length, byteArrayOutputStream);
    } catch (Exception exception) {
      throw new DecoderException("unable to decode base32 data: " + exception.getMessage(), exception);
    } 
    return byteArrayOutputStream.toByteArray();
  }
  
  public static byte[] decode(String paramString) {
    int i = paramString.length() / 8 * 5;
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(i);
    try {
      encoder.decode(paramString, byteArrayOutputStream);
    } catch (Exception exception) {
      throw new DecoderException("unable to decode base32 string: " + exception.getMessage(), exception);
    } 
    return byteArrayOutputStream.toByteArray();
  }
  
  public static int decode(String paramString, OutputStream paramOutputStream) throws IOException {
    return encoder.decode(paramString, paramOutputStream);
  }
  
  public static int decode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) {
    try {
      return encoder.decode(paramArrayOfbyte, paramInt1, paramInt2, paramOutputStream);
    } catch (Exception exception) {
      throw new DecoderException("unable to decode base32 data: " + exception.getMessage(), exception);
    } 
  }
}
