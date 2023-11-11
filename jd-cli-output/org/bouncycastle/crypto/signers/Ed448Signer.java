package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

public class Ed448Signer implements Signer {
  private final Buffer buffer = new Buffer();
  
  private final byte[] context;
  
  private boolean forSigning;
  
  private Ed448PrivateKeyParameters privateKey;
  
  private Ed448PublicKeyParameters publicKey;
  
  public Ed448Signer(byte[] paramArrayOfbyte) {
    this.context = Arrays.clone(paramArrayOfbyte);
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forSigning = paramBoolean;
    if (paramBoolean) {
      this.privateKey = (Ed448PrivateKeyParameters)paramCipherParameters;
      this.publicKey = null;
    } else {
      this.privateKey = null;
      this.publicKey = (Ed448PublicKeyParameters)paramCipherParameters;
    } 
    reset();
  }
  
  public void update(byte paramByte) {
    this.buffer.write(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.buffer.write(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public byte[] generateSignature() {
    if (!this.forSigning || null == this.privateKey)
      throw new IllegalStateException("Ed448Signer not initialised for signature generation."); 
    return this.buffer.generateSignature(this.privateKey, this.context);
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte) {
    if (this.forSigning || null == this.publicKey)
      throw new IllegalStateException("Ed448Signer not initialised for verification"); 
    return this.buffer.verifySignature(this.publicKey, this.context, paramArrayOfbyte);
  }
  
  public void reset() {
    this.buffer.reset();
  }
  
  private static class Buffer extends ByteArrayOutputStream {
    private Buffer() {}
    
    synchronized byte[] generateSignature(Ed448PrivateKeyParameters param1Ed448PrivateKeyParameters, byte[] param1ArrayOfbyte) {
      byte[] arrayOfByte = new byte[114];
      param1Ed448PrivateKeyParameters.sign(0, param1ArrayOfbyte, this.buf, 0, this.count, arrayOfByte, 0);
      reset();
      return arrayOfByte;
    }
    
    synchronized boolean verifySignature(Ed448PublicKeyParameters param1Ed448PublicKeyParameters, byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2) {
      if (114 != param1ArrayOfbyte2.length) {
        reset();
        return false;
      } 
      byte[] arrayOfByte = param1Ed448PublicKeyParameters.getEncoded();
      boolean bool = Ed448.verify(param1ArrayOfbyte2, 0, arrayOfByte, 0, param1ArrayOfbyte1, this.buf, 0, this.count);
      reset();
      return bool;
    }
    
    public synchronized void reset() {
      Arrays.fill(this.buf, 0, this.count, (byte)0);
      this.count = 0;
    }
  }
}
