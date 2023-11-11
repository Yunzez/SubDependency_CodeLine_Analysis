package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class X25519PrivateKeyParameters extends AsymmetricKeyParameter {
  public static final int KEY_SIZE = 32;
  
  public static final int SECRET_SIZE = 32;
  
  private final byte[] data = new byte[32];
  
  public X25519PrivateKeyParameters(SecureRandom paramSecureRandom) {
    super(true);
    X25519.generatePrivateKey(paramSecureRandom, this.data);
  }
  
  public X25519PrivateKeyParameters(byte[] paramArrayOfbyte) {
    this(validate(paramArrayOfbyte), 0);
  }
  
  public X25519PrivateKeyParameters(byte[] paramArrayOfbyte, int paramInt) {
    super(true);
    System.arraycopy(paramArrayOfbyte, paramInt, this.data, 0, 32);
  }
  
  public X25519PrivateKeyParameters(InputStream paramInputStream) throws IOException {
    super(true);
    if (32 != Streams.readFully(paramInputStream, this.data))
      throw new EOFException("EOF encountered in middle of X25519 private key"); 
  }
  
  public void encode(byte[] paramArrayOfbyte, int paramInt) {
    System.arraycopy(this.data, 0, paramArrayOfbyte, paramInt, 32);
  }
  
  public byte[] getEncoded() {
    return Arrays.clone(this.data);
  }
  
  public X25519PublicKeyParameters generatePublicKey() {
    byte[] arrayOfByte = new byte[32];
    X25519.generatePublicKey(this.data, 0, arrayOfByte, 0);
    return new X25519PublicKeyParameters(arrayOfByte, 0);
  }
  
  public void generateSecret(X25519PublicKeyParameters paramX25519PublicKeyParameters, byte[] paramArrayOfbyte, int paramInt) {
    byte[] arrayOfByte = new byte[32];
    paramX25519PublicKeyParameters.encode(arrayOfByte, 0);
    if (!X25519.calculateAgreement(this.data, 0, arrayOfByte, 0, paramArrayOfbyte, paramInt))
      throw new IllegalStateException("X25519 agreement failed"); 
  }
  
  private static byte[] validate(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != 32)
      throw new IllegalArgumentException("'buf' must have length 32"); 
    return paramArrayOfbyte;
  }
}
