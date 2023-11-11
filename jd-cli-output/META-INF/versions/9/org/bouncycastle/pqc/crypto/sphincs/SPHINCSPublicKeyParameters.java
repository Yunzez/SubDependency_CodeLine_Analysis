package META-INF.versions.9.org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.util.Arrays;

public class SPHINCSPublicKeyParameters extends SPHINCSKeyParameters {
  private final byte[] keyData;
  
  public SPHINCSPublicKeyParameters(byte[] paramArrayOfbyte) {
    super(false, null);
    this.keyData = Arrays.clone(paramArrayOfbyte);
  }
  
  public SPHINCSPublicKeyParameters(byte[] paramArrayOfbyte, String paramString) {
    super(false, paramString);
    this.keyData = Arrays.clone(paramArrayOfbyte);
  }
  
  public byte[] getKeyData() {
    return Arrays.clone(this.keyData);
  }
}
