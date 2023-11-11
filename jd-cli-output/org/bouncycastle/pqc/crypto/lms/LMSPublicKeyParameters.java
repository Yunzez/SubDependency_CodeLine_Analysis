package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class LMSPublicKeyParameters extends LMSKeyParameters implements LMSContextBasedVerifier {
  private final LMSigParameters parameterSet;
  
  private final LMOtsParameters lmOtsType;
  
  private final byte[] I;
  
  private final byte[] T1;
  
  public LMSPublicKeyParameters(LMSigParameters paramLMSigParameters, LMOtsParameters paramLMOtsParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    super(false);
    this.parameterSet = paramLMSigParameters;
    this.lmOtsType = paramLMOtsParameters;
    this.I = Arrays.clone(paramArrayOfbyte2);
    this.T1 = Arrays.clone(paramArrayOfbyte1);
  }
  
  public static LMSPublicKeyParameters getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof LMSPublicKeyParameters)
      return (LMSPublicKeyParameters)paramObject; 
    if (paramObject instanceof DataInputStream) {
      int i = ((DataInputStream)paramObject).readInt();
      LMSigParameters lMSigParameters = LMSigParameters.getParametersForType(i);
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[] arrayOfByte1 = new byte[16];
      ((DataInputStream)paramObject).readFully(arrayOfByte1);
      byte[] arrayOfByte2 = new byte[lMSigParameters.getM()];
      ((DataInputStream)paramObject).readFully(arrayOfByte2);
      return new LMSPublicKeyParameters(lMSigParameters, lMOtsParameters, arrayOfByte2, arrayOfByte1);
    } 
    if (paramObject instanceof byte[]) {
      DataInputStream dataInputStream = null;
      try {
        dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[])paramObject));
        return getInstance(dataInputStream);
      } finally {
        if (dataInputStream != null)
          dataInputStream.close(); 
      } 
    } 
    if (paramObject instanceof InputStream)
      return getInstance(Streams.readAll((InputStream)paramObject)); 
    throw new IllegalArgumentException("cannot parse " + paramObject);
  }
  
  public byte[] getEncoded() throws IOException {
    return toByteArray();
  }
  
  public LMSigParameters getSigParameters() {
    return this.parameterSet;
  }
  
  public LMOtsParameters getOtsParameters() {
    return this.lmOtsType;
  }
  
  public LMSParameters getLMSParameters() {
    return new LMSParameters(getSigParameters(), getOtsParameters());
  }
  
  public byte[] getT1() {
    return Arrays.clone(this.T1);
  }
  
  boolean matchesT1(byte[] paramArrayOfbyte) {
    return Arrays.constantTimeAreEqual(this.T1, paramArrayOfbyte);
  }
  
  public byte[] getI() {
    return Arrays.clone(this.I);
  }
  
  byte[] refI() {
    return this.I;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    LMSPublicKeyParameters lMSPublicKeyParameters = (LMSPublicKeyParameters)paramObject;
    return !this.parameterSet.equals(lMSPublicKeyParameters.parameterSet) ? false : (!this.lmOtsType.equals(lMSPublicKeyParameters.lmOtsType) ? false : (!Arrays.areEqual(this.I, lMSPublicKeyParameters.I) ? false : Arrays.areEqual(this.T1, lMSPublicKeyParameters.T1)));
  }
  
  public int hashCode() {
    null = this.parameterSet.hashCode();
    null = 31 * null + this.lmOtsType.hashCode();
    null = 31 * null + Arrays.hashCode(this.I);
    return 31 * null + Arrays.hashCode(this.T1);
  }
  
  byte[] toByteArray() {
    return Composer.compose().u32str(this.parameterSet.getType()).u32str(this.lmOtsType.getType()).bytes(this.I).bytes(this.T1).build();
  }
  
  public LMSContext generateLMSContext(byte[] paramArrayOfbyte) {
    try {
      return generateOtsContext(LMSSignature.getInstance(paramArrayOfbyte));
    } catch (IOException iOException) {
      throw new IllegalStateException("cannot parse signature: " + iOException.getMessage());
    } 
  }
  
  LMSContext generateOtsContext(LMSSignature paramLMSSignature) {
    int i = getOtsParameters().getType();
    if (paramLMSSignature.getOtsSignature().getType().getType() != i)
      throw new IllegalArgumentException("ots type from lsm signature does not match ots signature type from embedded ots signature"); 
    return (new LMOtsPublicKey(LMOtsParameters.getParametersForType(i), this.I, paramLMSSignature.getQ(), null)).createOtsContext(paramLMSSignature);
  }
  
  public boolean verify(LMSContext paramLMSContext) {
    return LMS.verifySignature(this, paramLMSContext);
  }
}
