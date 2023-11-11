package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class X448PrivateKeyParameters extends AsymmetricKeyParameter {
  public static final int KEY_SIZE = 56;
  
  public static final int SECRET_SIZE = 56;
  
  private final byte[] data = new byte[56];
  
  public X448PrivateKeyParameters(SecureRandom paramSecureRandom) {
    super(true);
    X448.generatePrivateKey(paramSecureRandom, this.data);
  }
  
  public X448PrivateKeyParameters(byte[] paramArrayOfbyte) {
    this(validate(paramArrayOfbyte), 0);
  }
  
  public X448PrivateKeyParameters(byte[] paramArrayOfbyte, int paramInt) {
    super(true);
    System.arraycopy(paramArrayOfbyte, paramInt, this.data, 0, 56);
  }
  
  public X448PrivateKeyParameters(InputStream paramInputStream) throws IOException {
    super(true);
    if (56 != Streams.readFully(paramInputStream, this.data))
      throw new EOFException("EOF encountered in middle of X448 private key"); 
  }
  
  public void encode(byte[] paramArrayOfbyte, int paramInt) {
    System.arraycopy(this.data, 0, paramArrayOfbyte, paramInt, 56);
  }
  
  public byte[] getEncoded() {
    return Arrays.clone(this.data);
  }
  
  public X448PublicKeyParameters generatePublicKey() {
    byte[] arrayOfByte = new byte[56];
    X448.generatePublicKey(this.data, 0, arrayOfByte, 0);
    return new X448PublicKeyParameters(arrayOfByte, 0);
  }
  
  public void generateSecret(X448PublicKeyParameters paramX448PublicKeyParameters, byte[] paramArrayOfbyte, int paramInt) {
    byte[] arrayOfByte = new byte[56];
    paramX448PublicKeyParameters.encode(arrayOfByte, 0);
    if (!X448.calculateAgreement(this.data, 0, arrayOfByte, 0, paramArrayOfbyte, paramInt))
      throw new IllegalStateException("X448 agreement failed"); 
  }
  
  private static byte[] validate(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != 56)
      throw new IllegalArgumentException("'buf' must have length 56"); 
    return paramArrayOfbyte;
  }
}
