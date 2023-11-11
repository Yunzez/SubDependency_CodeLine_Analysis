package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class SPHINCSPlusSigner implements MessageSigner {
  private SPHINCSPlusPrivateKeyParameters privKey;
  
  private SPHINCSPlusPublicKeyParameters pubKey;
  
  private SecureRandom random;
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (paramBoolean) {
      if (paramCipherParameters instanceof ParametersWithRandom) {
        this.privKey = (SPHINCSPlusPrivateKeyParameters)((ParametersWithRandom)paramCipherParameters).getParameters();
        this.random = ((ParametersWithRandom)paramCipherParameters).getRandom();
      } else {
        this.privKey = (SPHINCSPlusPrivateKeyParameters)paramCipherParameters;
      } 
    } else {
      this.pubKey = (SPHINCSPlusPublicKeyParameters)paramCipherParameters;
    } 
  }
  
  public byte[] generateSignature(byte[] paramArrayOfbyte) {
    SPHINCSPlusEngine sPHINCSPlusEngine = this.privKey.getParameters().getEngine();
    byte[] arrayOfByte1 = new byte[sPHINCSPlusEngine.N];
    if (this.random != null)
      this.random.nextBytes(arrayOfByte1); 
    Fors fors = new Fors(sPHINCSPlusEngine);
    byte[] arrayOfByte2 = sPHINCSPlusEngine.PRF_msg(this.privKey.sk.prf, arrayOfByte1, paramArrayOfbyte);
    IndexedDigest indexedDigest = sPHINCSPlusEngine.H_msg(arrayOfByte2, this.privKey.pk.seed, this.privKey.pk.root, paramArrayOfbyte);
    byte[] arrayOfByte3 = indexedDigest.digest;
    long l = indexedDigest.idx_tree;
    int i = indexedDigest.idx_leaf;
    ADRS aDRS1 = new ADRS();
    aDRS1.setType(3);
    aDRS1.setTreeAddress(l);
    aDRS1.setKeyPairAddress(i);
    SIG_FORS[] arrayOfSIG_FORS = fors.sign(arrayOfByte3, this.privKey.sk.seed, this.privKey.pk.seed, aDRS1);
    byte[] arrayOfByte4 = fors.pkFromSig(arrayOfSIG_FORS, arrayOfByte3, this.privKey.pk.seed, aDRS1);
    ADRS aDRS2 = new ADRS();
    aDRS2.setType(2);
    HT hT = new HT(sPHINCSPlusEngine, this.privKey.getSeed(), this.privKey.getPublicSeed());
    byte[] arrayOfByte5 = hT.sign(arrayOfByte4, l, i);
    byte[][] arrayOfByte = new byte[arrayOfSIG_FORS.length + 2][];
    arrayOfByte[0] = arrayOfByte2;
    for (byte b = 0; b != arrayOfSIG_FORS.length; b++)
      arrayOfByte[1 + b] = Arrays.concatenate((arrayOfSIG_FORS[b]).sk, Arrays.concatenate((arrayOfSIG_FORS[b]).authPath)); 
    arrayOfByte[arrayOfByte.length - 1] = arrayOfByte5;
    return Arrays.concatenate(arrayOfByte);
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    SPHINCSPlusEngine sPHINCSPlusEngine = this.pubKey.getParameters().getEngine();
    ADRS aDRS = new ADRS();
    SIG sIG = new SIG(sPHINCSPlusEngine.N, sPHINCSPlusEngine.K, sPHINCSPlusEngine.A, sPHINCSPlusEngine.D, sPHINCSPlusEngine.H_PRIME, sPHINCSPlusEngine.WOTS_LEN, paramArrayOfbyte2);
    byte[] arrayOfByte1 = sIG.getR();
    SIG_FORS[] arrayOfSIG_FORS = sIG.getSIG_FORS();
    SIG_XMSS[] arrayOfSIG_XMSS = sIG.getSIG_HT();
    IndexedDigest indexedDigest = sPHINCSPlusEngine.H_msg(arrayOfByte1, this.pubKey.getSeed(), this.pubKey.getRoot(), paramArrayOfbyte1);
    byte[] arrayOfByte2 = indexedDigest.digest;
    long l = indexedDigest.idx_tree;
    int i = indexedDigest.idx_leaf;
    aDRS.setLayerAddress(0);
    aDRS.setTreeAddress(l);
    aDRS.setType(3);
    aDRS.setKeyPairAddress(i);
    byte[] arrayOfByte3 = (new Fors(sPHINCSPlusEngine)).pkFromSig(arrayOfSIG_FORS, arrayOfByte2, this.pubKey.getSeed(), aDRS);
    aDRS.setType(2);
    HT hT = new HT(sPHINCSPlusEngine, null, this.pubKey.getSeed());
    return hT.verify(arrayOfByte3, arrayOfSIG_XMSS, this.pubKey.getSeed(), l, i, this.pubKey.getRoot());
  }
}
