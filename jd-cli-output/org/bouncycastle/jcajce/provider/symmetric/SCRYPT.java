package org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

public class SCRYPT {
  public static class BasePBKDF2 extends BaseSecretKeyFactory {
    private int scheme;
    
    public BasePBKDF2(String param1String, int param1Int) {
      super(param1String, MiscObjectIdentifiers.id_scrypt);
      this.scheme = param1Int;
    }
    
    protected SecretKey engineGenerateSecret(KeySpec param1KeySpec) throws InvalidKeySpecException {
      if (param1KeySpec instanceof ScryptKeySpec) {
        ScryptKeySpec scryptKeySpec = (ScryptKeySpec)param1KeySpec;
        if (scryptKeySpec.getSalt() == null)
          throw new IllegalArgumentException("Salt S must be provided."); 
        if (scryptKeySpec.getCostParameter() <= 1)
          throw new IllegalArgumentException("Cost parameter N must be > 1."); 
        if (scryptKeySpec.getKeyLength() <= 0)
          throw new InvalidKeySpecException("positive key length required: " + scryptKeySpec.getKeyLength()); 
        if ((scryptKeySpec.getPassword()).length == 0)
          throw new IllegalArgumentException("password empty"); 
        KeyParameter keyParameter = new KeyParameter(SCrypt.generate(PasswordConverter.UTF8.convert(scryptKeySpec.getPassword()), scryptKeySpec.getSalt(), scryptKeySpec.getCostParameter(), scryptKeySpec.getBlockSize(), scryptKeySpec.getParallelizationParameter(), scryptKeySpec.getKeyLength() / 8));
        return new BCPBEKey(this.algName, keyParameter);
      } 
      throw new InvalidKeySpecException("Invalid KeySpec");
    }
  }
  
  public static class Mappings extends AlgorithmProvider {
    private static final String PREFIX = SCRYPT.class.getName();
    
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8");
      param1ConfigurableProvider.addAlgorithm("SecretKeyFactory", MiscObjectIdentifiers.id_scrypt, PREFIX + "$ScryptWithUTF8");
    }
  }
  
  public static class ScryptWithUTF8 extends BasePBKDF2 {
    public ScryptWithUTF8() {
      super("SCRYPT", 5);
    }
  }
}
