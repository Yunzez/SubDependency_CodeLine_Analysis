package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public final class Ed25519PrivateKeyParameters extends AsymmetricKeyParameter {
  public static final int KEY_SIZE = 32;
  
  public static final int SIGNATURE_SIZE = 64;
  
  private final byte[] data = new byte[32];
  
  private Ed25519PublicKeyParameters cachedPublicKey;
  
  public Ed25519PrivateKeyParameters(SecureRandom paramSecureRandom) {
    super(true);
    Ed25519.generatePrivateKey(paramSecureRandom, this.data);
  }
  
  public Ed25519PrivateKeyParameters(byte[] paramArrayOfbyte) {
    this(validate(paramArrayOfbyte), 0);
  }
  
  public Ed25519PrivateKeyParameters(byte[] paramArrayOfbyte, int paramInt) {
    super(true);
    System.arraycopy(paramArrayOfbyte, paramInt, this.data, 0, 32);
  }
  
  public Ed25519PrivateKeyParameters(InputStream paramInputStream) throws IOException {
    super(true);
    if (32 != Streams.readFully(paramInputStream, this.data))
      throw new EOFException("EOF encountered in middle of Ed25519 private key"); 
  }
  
  public void encode(byte[] paramArrayOfbyte, int paramInt) {
    System.arraycopy(this.data, 0, paramArrayOfbyte, paramInt, 32);
  }
  
  public byte[] getEncoded() {
    return Arrays.clone(this.data);
  }
  
  public Ed25519PublicKeyParameters generatePublicKey() {
    synchronized (this.data) {
      if (null == this.cachedPublicKey) {
        byte[] arrayOfByte = new byte[32];
        Ed25519.generatePublicKey(this.data, 0, arrayOfByte, 0);
        this.cachedPublicKey = new Ed25519PublicKeyParameters(arrayOfByte, 0);
      } 
      return this.cachedPublicKey;
    } 
  }
  
  public void sign(int paramInt1, Ed25519PublicKeyParameters paramEd25519PublicKeyParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt2, int paramInt3, byte[] paramArrayOfbyte3, int paramInt4) {
    sign(paramInt1, paramArrayOfbyte1, paramArrayOfbyte2, paramInt2, paramInt3, paramArrayOfbyte3, paramInt4);
  }
  
  public void sign(int paramInt1, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt2, int paramInt3, byte[] paramArrayOfbyte3, int paramInt4) {
    Ed25519PublicKeyParameters ed25519PublicKeyParameters = generatePublicKey();
    byte[] arrayOfByte = new byte[32];
    ed25519PublicKeyParameters.encode(arrayOfByte, 0);
    switch (paramInt1) {
      case 0:
        if (null != paramArrayOfbyte1)
          throw new IllegalArgumentException("ctx"); 
        Ed25519.sign(this.data, 0, arrayOfByte, 0, paramArrayOfbyte2, paramInt2, paramInt3, paramArrayOfbyte3, paramInt4);
        return;
      case 1:
        Ed25519.sign(this.data, 0, arrayOfByte, 0, paramArrayOfbyte1, paramArrayOfbyte2, paramInt2, paramInt3, paramArrayOfbyte3, paramInt4);
        return;
      case 2:
        if (64 != paramInt3)
          throw new IllegalArgumentException("msgLen"); 
        Ed25519.signPrehash(this.data, 0, arrayOfByte, 0, paramArrayOfbyte1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, paramInt4);
        return;
    } 
    throw new IllegalArgumentException("algorithm");
  }
  
  private static byte[] validate(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != 32)
      throw new IllegalArgumentException("'buf' must have length 32"); 
    return paramArrayOfbyte;
  }
}
