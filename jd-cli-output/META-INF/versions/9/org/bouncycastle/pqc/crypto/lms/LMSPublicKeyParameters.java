package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey;
import org.bouncycastle.pqc.crypto.lms.LMS;
import org.bouncycastle.pqc.crypto.lms.LMSContext;
import org.bouncycastle.pqc.crypto.lms.LMSContextBasedVerifier;
import org.bouncycastle.pqc.crypto.lms.LMSKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSignature;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
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
  
  public static org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters)
      return (org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters)paramObject; 
    if (paramObject instanceof DataInputStream) {
      int i = ((DataInputStream)paramObject).readInt();
      LMSigParameters lMSigParameters = LMSigParameters.getParametersForType(i);
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[] arrayOfByte1 = new byte[16];
      ((DataInputStream)paramObject).readFully(arrayOfByte1);
      byte[] arrayOfByte2 = new byte[lMSigParameters.getM()];
      ((DataInputStream)paramObject).readFully(arrayOfByte2);
      return new org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters(lMSigParameters, lMOtsParameters, arrayOfByte2, arrayOfByte1);
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
    org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters lMSPublicKeyParameters = (org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters)paramObject;
    if (!this.parameterSet.equals(lMSPublicKeyParameters.parameterSet))
      return false; 
    if (!this.lmOtsType.equals(lMSPublicKeyParameters.lmOtsType))
      return false; 
    if (!Arrays.areEqual(this.I, lMSPublicKeyParameters.I))
      return false; 
    return Arrays.areEqual(this.T1, lMSPublicKeyParameters.T1);
  }
  
  public int hashCode() {
    int i = this.parameterSet.hashCode();
    i = 31 * i + this.lmOtsType.hashCode();
    i = 31 * i + Arrays.hashCode(this.I);
    i = 31 * i + Arrays.hashCode(this.T1);
    return i;
  }
  
  byte[] toByteArray() {
    return Composer.compose()
      .u32str(this.parameterSet.getType())
      .u32str(this.lmOtsType.getType())
      .bytes(this.I)
      .bytes(this.T1)
      .build();
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
