package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.io.Streams;

public class HSSPublicKeyParameters extends LMSKeyParameters implements LMSContextBasedVerifier {
  private final int l;
  
  private final LMSPublicKeyParameters lmsPublicKey;
  
  public HSSPublicKeyParameters(int paramInt, LMSPublicKeyParameters paramLMSPublicKeyParameters) {
    super(false);
    this.l = paramInt;
    this.lmsPublicKey = paramLMSPublicKeyParameters;
  }
  
  public static HSSPublicKeyParameters getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof HSSPublicKeyParameters)
      return (HSSPublicKeyParameters)paramObject; 
    if (paramObject instanceof DataInputStream) {
      int i = ((DataInputStream)paramObject).readInt();
      LMSPublicKeyParameters lMSPublicKeyParameters = LMSPublicKeyParameters.getInstance(paramObject);
      return new HSSPublicKeyParameters(i, lMSPublicKeyParameters);
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
  
  public int getL() {
    return this.l;
  }
  
  public LMSPublicKeyParameters getLMSPublicKey() {
    return this.lmsPublicKey;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    HSSPublicKeyParameters hSSPublicKeyParameters = (HSSPublicKeyParameters)paramObject;
    return (this.l != hSSPublicKeyParameters.l) ? false : this.lmsPublicKey.equals(hSSPublicKeyParameters.lmsPublicKey);
  }
  
  public int hashCode() {
    null = this.l;
    return 31 * null + this.lmsPublicKey.hashCode();
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose().u32str(this.l).bytes(this.lmsPublicKey.getEncoded()).build();
  }
  
  public LMSContext generateLMSContext(byte[] paramArrayOfbyte) {
    HSSSignature hSSSignature;
    try {
      hSSSignature = HSSSignature.getInstance(paramArrayOfbyte, getL());
    } catch (IOException iOException) {
      throw new IllegalStateException("cannot parse signature: " + iOException.getMessage());
    } 
    LMSSignedPubKey[] arrayOfLMSSignedPubKey = hSSSignature.getSignedPubKey();
    LMSPublicKeyParameters lMSPublicKeyParameters = arrayOfLMSSignedPubKey[arrayOfLMSSignedPubKey.length - 1].getPublicKey();
    return lMSPublicKeyParameters.generateOtsContext(hSSSignature.getSignature()).withSignedPublicKeys(arrayOfLMSSignedPubKey);
  }
  
  public boolean verify(LMSContext paramLMSContext) {
    boolean bool = false;
    LMSSignedPubKey[] arrayOfLMSSignedPubKey = paramLMSContext.getSignedPubKeys();
    if (arrayOfLMSSignedPubKey.length != getL() - 1)
      return false; 
    LMSPublicKeyParameters lMSPublicKeyParameters = getLMSPublicKey();
    for (byte b = 0; b < arrayOfLMSSignedPubKey.length; b++) {
      LMSSignature lMSSignature = arrayOfLMSSignedPubKey[b].getSignature();
      byte[] arrayOfByte = arrayOfLMSSignedPubKey[b].getPublicKey().toByteArray();
      if (!LMS.verifySignature(lMSPublicKeyParameters, lMSSignature, arrayOfByte))
        bool = true; 
      lMSPublicKeyParameters = arrayOfLMSSignedPubKey[b].getPublicKey();
    } 
    return (!bool) & lMSPublicKeyParameters.verify(paramLMSContext);
  }
}
