package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class QTESLASigner implements MessageSigner {
  private QTESLAPublicKeyParameters publicKey;
  
  private QTESLAPrivateKeyParameters privateKey;
  
  private SecureRandom secureRandom;
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (paramBoolean) {
      if (paramCipherParameters instanceof ParametersWithRandom) {
        this.secureRandom = ((ParametersWithRandom)paramCipherParameters).getRandom();
        this.privateKey = (QTESLAPrivateKeyParameters)((ParametersWithRandom)paramCipherParameters).getParameters();
      } else {
        this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
        this.privateKey = (QTESLAPrivateKeyParameters)paramCipherParameters;
      } 
      this.publicKey = null;
      QTESLASecurityCategory.validate(this.privateKey.getSecurityCategory());
    } else {
      this.privateKey = null;
      this.publicKey = (QTESLAPublicKeyParameters)paramCipherParameters;
      QTESLASecurityCategory.validate(this.publicKey.getSecurityCategory());
    } 
  }
  
  public byte[] generateSignature(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[QTESLASecurityCategory.getSignatureSize(this.privateKey.getSecurityCategory())];
    switch (this.privateKey.getSecurityCategory()) {
      case 5:
        QTesla1p.generateSignature(arrayOfByte, paramArrayOfbyte, 0, paramArrayOfbyte.length, this.privateKey.getSecret(), this.secureRandom);
        return arrayOfByte;
      case 6:
        QTesla3p.generateSignature(arrayOfByte, paramArrayOfbyte, 0, paramArrayOfbyte.length, this.privateKey.getSecret(), this.secureRandom);
        return arrayOfByte;
    } 
    throw new IllegalArgumentException("unknown security category: " + this.privateKey.getSecurityCategory());
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i;
    switch (this.publicKey.getSecurityCategory()) {
      case 5:
        i = QTesla1p.verifying(paramArrayOfbyte1, paramArrayOfbyte2, 0, paramArrayOfbyte2.length, this.publicKey.getPublicData());
        break;
      case 6:
        i = QTesla3p.verifying(paramArrayOfbyte1, paramArrayOfbyte2, 0, paramArrayOfbyte2.length, this.publicKey.getPublicData());
        break;
      default:
        throw new IllegalArgumentException("unknown security category: " + this.publicKey.getSecurityCategory());
    } 
    return (0 == i);
  }
}
