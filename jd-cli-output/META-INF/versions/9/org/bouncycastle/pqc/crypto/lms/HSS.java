package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.util.Arrays;
import java.util.List;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSSignature;
import org.bouncycastle.pqc.crypto.lms.LMS;
import org.bouncycastle.pqc.crypto.lms.LMSContext;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSignature;
import org.bouncycastle.pqc.crypto.lms.LMSSignedPubKey;

class HSS {
  public static HSSPrivateKeyParameters generateHSSKeyPair(HSSKeyGenerationParameters paramHSSKeyGenerationParameters) {
    LMSPrivateKeyParameters[] arrayOfLMSPrivateKeyParameters = new LMSPrivateKeyParameters[paramHSSKeyGenerationParameters.getDepth()];
    LMSSignature[] arrayOfLMSSignature = new LMSSignature[paramHSSKeyGenerationParameters.getDepth() - 1];
    byte[] arrayOfByte1 = new byte[32];
    paramHSSKeyGenerationParameters.getRandom().nextBytes(arrayOfByte1);
    byte[] arrayOfByte2 = new byte[16];
    paramHSSKeyGenerationParameters.getRandom().nextBytes(arrayOfByte2);
    byte[] arrayOfByte3 = new byte[0];
    long l = 1L;
    for (byte b = 0; b < arrayOfLMSPrivateKeyParameters.length; b++) {
      if (b == 0) {
        arrayOfLMSPrivateKeyParameters[b] = new LMSPrivateKeyParameters(paramHSSKeyGenerationParameters
            .getLmsParameters()[b].getLMSigParam(), paramHSSKeyGenerationParameters
            .getLmsParameters()[b].getLMOTSParam(), 0, arrayOfByte2, 1 << paramHSSKeyGenerationParameters

            
            .getLmsParameters()[b].getLMSigParam().getH(), arrayOfByte1);
      } else {
        arrayOfLMSPrivateKeyParameters[b] = new PlaceholderLMSPrivateKey(paramHSSKeyGenerationParameters
            .getLmsParameters()[b].getLMSigParam(), paramHSSKeyGenerationParameters
            .getLmsParameters()[b].getLMOTSParam(), -1, arrayOfByte3, 1 << paramHSSKeyGenerationParameters

            
            .getLmsParameters()[b].getLMSigParam().getH(), arrayOfByte3);
      } 
      l *= (1 << paramHSSKeyGenerationParameters.getLmsParameters()[b].getLMSigParam().getH());
    } 
    if (l == 0L)
      l = Long.MAX_VALUE; 
    return new HSSPrivateKeyParameters(paramHSSKeyGenerationParameters
        .getDepth(), 
        Arrays.asList(arrayOfLMSPrivateKeyParameters), 
        Arrays.asList(arrayOfLMSSignature), 0L, l);
  }
  
  public static void incrementIndex(HSSPrivateKeyParameters paramHSSPrivateKeyParameters) {
    synchronized (paramHSSPrivateKeyParameters) {
      rangeTestKeys(paramHSSPrivateKeyParameters);
      paramHSSPrivateKeyParameters.incIndex();
      ((LMSPrivateKeyParameters)paramHSSPrivateKeyParameters.getKeys().get(paramHSSPrivateKeyParameters.getL() - 1)).incIndex();
    } 
  }
  
  static void rangeTestKeys(HSSPrivateKeyParameters paramHSSPrivateKeyParameters) {
    synchronized (paramHSSPrivateKeyParameters) {
      if (paramHSSPrivateKeyParameters.getIndex() >= paramHSSPrivateKeyParameters.getIndexLimit())
        throw new ExhaustedPrivateKeyException("hss private key" + (
            
            paramHSSPrivateKeyParameters.isShard() ? " shard" : "") + " is exhausted"); 
      int i = paramHSSPrivateKeyParameters.getL();
      int j = i;
      List<LMSPrivateKeyParameters> list = paramHSSPrivateKeyParameters.getKeys();
      while (((LMSPrivateKeyParameters)list.get(j - 1)).getIndex() == 1 << ((LMSPrivateKeyParameters)list.get(j - 1)).getSigParameters().getH()) {
        j--;
        if (j == 0)
          throw new ExhaustedPrivateKeyException("hss private key" + (
              
              paramHSSPrivateKeyParameters.isShard() ? " shard" : "") + " is exhausted the maximum limit for this HSS private key"); 
      } 
      while (j < i) {
        paramHSSPrivateKeyParameters.replaceConsumedKey(j);
        j++;
      } 
    } 
  }
  
  public static HSSSignature generateSignature(HSSPrivateKeyParameters paramHSSPrivateKeyParameters, byte[] paramArrayOfbyte) {
    LMSSignedPubKey[] arrayOfLMSSignedPubKey;
    LMSPrivateKeyParameters lMSPrivateKeyParameters;
    int i = paramHSSPrivateKeyParameters.getL();
    synchronized (paramHSSPrivateKeyParameters) {
      rangeTestKeys(paramHSSPrivateKeyParameters);
      List<LMSPrivateKeyParameters> list = paramHSSPrivateKeyParameters.getKeys();
      List<LMSSignature> list1 = paramHSSPrivateKeyParameters.getSig();
      lMSPrivateKeyParameters = paramHSSPrivateKeyParameters.getKeys().get(i - 1);
      int j = 0;
      arrayOfLMSSignedPubKey = new LMSSignedPubKey[i - 1];
      while (j < i - 1) {
        arrayOfLMSSignedPubKey[j] = new LMSSignedPubKey(list1
            .get(j), ((LMSPrivateKeyParameters)list
            .get(j + 1)).getPublicKey());
        j++;
      } 
      paramHSSPrivateKeyParameters.incIndex();
    } 
    LMSContext lMSContext = lMSPrivateKeyParameters.generateLMSContext().withSignedPublicKeys(arrayOfLMSSignedPubKey);
    lMSContext.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
    return generateSignature(i, lMSContext);
  }
  
  public static HSSSignature generateSignature(int paramInt, LMSContext paramLMSContext) {
    return new HSSSignature(paramInt - 1, paramLMSContext.getSignedPubKeys(), LMS.generateSign(paramLMSContext));
  }
  
  public static boolean verifySignature(HSSPublicKeyParameters paramHSSPublicKeyParameters, HSSSignature paramHSSSignature, byte[] paramArrayOfbyte) {
    int i = paramHSSSignature.getlMinus1();
    if (i + 1 != paramHSSPublicKeyParameters.getL())
      return false; 
    LMSSignature[] arrayOfLMSSignature = new LMSSignature[i + 1];
    LMSPublicKeyParameters[] arrayOfLMSPublicKeyParameters = new LMSPublicKeyParameters[i];
    for (byte b1 = 0; b1 < i; b1++) {
      arrayOfLMSSignature[b1] = paramHSSSignature.getSignedPubKey()[b1].getSignature();
      arrayOfLMSPublicKeyParameters[b1] = paramHSSSignature.getSignedPubKey()[b1].getPublicKey();
    } 
    arrayOfLMSSignature[i] = paramHSSSignature.getSignature();
    LMSPublicKeyParameters lMSPublicKeyParameters = paramHSSPublicKeyParameters.getLMSPublicKey();
    for (byte b2 = 0; b2 < i; b2++) {
      LMSSignature lMSSignature = arrayOfLMSSignature[b2];
      byte[] arrayOfByte = arrayOfLMSPublicKeyParameters[b2].toByteArray();
      if (!LMS.verifySignature(lMSPublicKeyParameters, lMSSignature, arrayOfByte))
        return false; 
      try {
        lMSPublicKeyParameters = arrayOfLMSPublicKeyParameters[b2];
      } catch (Exception exception) {
        throw new IllegalStateException(exception.getMessage(), exception);
      } 
    } 
    return LMS.verifySignature(lMSPublicKeyParameters, arrayOfLMSSignature[i], paramArrayOfbyte);
  }
}
