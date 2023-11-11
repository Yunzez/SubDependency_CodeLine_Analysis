package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSignature;
import org.bouncycastle.pqc.crypto.lms.LMSSignedPubKey;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

public class HSSSignature implements Encodable {
  private final int lMinus1;
  
  private final LMSSignedPubKey[] signedPubKey;
  
  private final LMSSignature signature;
  
  public HSSSignature(int paramInt, LMSSignedPubKey[] paramArrayOfLMSSignedPubKey, LMSSignature paramLMSSignature) {
    this.lMinus1 = paramInt;
    this.signedPubKey = paramArrayOfLMSSignedPubKey;
    this.signature = paramLMSSignature;
  }
  
  public static org.bouncycastle.pqc.crypto.lms.HSSSignature getInstance(Object paramObject, int paramInt) throws IOException {
    if (paramObject instanceof org.bouncycastle.pqc.crypto.lms.HSSSignature)
      return (org.bouncycastle.pqc.crypto.lms.HSSSignature)paramObject; 
    if (paramObject instanceof DataInputStream) {
      int i = ((DataInputStream)paramObject).readInt();
      if (i != paramInt - 1)
        throw new IllegalStateException("nspk exceeded maxNspk"); 
      LMSSignedPubKey[] arrayOfLMSSignedPubKey = new LMSSignedPubKey[i];
      if (i != 0)
        for (byte b = 0; b < arrayOfLMSSignedPubKey.length; b++)
          arrayOfLMSSignedPubKey[b] = new LMSSignedPubKey(LMSSignature.getInstance(paramObject), LMSPublicKeyParameters.getInstance(paramObject));  
      LMSSignature lMSSignature = LMSSignature.getInstance(paramObject);
      return new org.bouncycastle.pqc.crypto.lms.HSSSignature(i, arrayOfLMSSignedPubKey, lMSSignature);
    } 
    if (paramObject instanceof byte[]) {
      DataInputStream dataInputStream = null;
      try {
        dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[])paramObject));
        return getInstance(dataInputStream, paramInt);
      } finally {
        if (dataInputStream != null)
          dataInputStream.close(); 
      } 
    } 
    if (paramObject instanceof InputStream)
      return getInstance(Streams.readAll((InputStream)paramObject), paramInt); 
    throw new IllegalArgumentException("cannot parse " + paramObject);
  }
  
  public int getlMinus1() {
    return this.lMinus1;
  }
  
  public LMSSignedPubKey[] getSignedPubKey() {
    return this.signedPubKey;
  }
  
  public LMSSignature getSignature() {
    return this.signature;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    org.bouncycastle.pqc.crypto.lms.HSSSignature hSSSignature = (org.bouncycastle.pqc.crypto.lms.HSSSignature)paramObject;
    if (this.lMinus1 != hSSSignature.lMinus1)
      return false; 
    if (this.signedPubKey.length != hSSSignature.signedPubKey.length)
      return false; 
    for (byte b = 0; b < this.signedPubKey.length; b++) {
      if (!this.signedPubKey[b].equals(hSSSignature.signedPubKey[b]))
        return false; 
    } 
    return (this.signature != null) ? this.signature.equals(hSSSignature.signature) : ((hSSSignature.signature == null));
  }
  
  public int hashCode() {
    int i = this.lMinus1;
    i = 31 * i + Arrays.hashCode((Object[])this.signedPubKey);
    i = 31 * i + ((this.signature != null) ? this.signature.hashCode() : 0);
    return i;
  }
  
  public byte[] getEncoded() throws IOException {
    Composer composer = Composer.compose();
    composer.u32str(this.lMinus1);
    if (this.signedPubKey != null)
      for (LMSSignedPubKey lMSSignedPubKey : this.signedPubKey)
        composer.bytes(lMSSignedPubKey);  
    composer.bytes(this.signature);
    return composer.build();
  }
}
