package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class SipHash128 {
  public static class KeyGen extends BaseKeyGenerator {
    public KeyGen() {
      super("SipHash128", 128, new CipherKeyGenerator());
    }
  }
  
  public static class Mac24 extends BaseMac {
    public Mac24() {
      super(new org.bouncycastle.crypto.macs.SipHash128());
    }
  }
  
  public static class Mac48 extends BaseMac {
    public Mac48() {
      super(new org.bouncycastle.crypto.macs.SipHash128(4, 8));
    }
  }
  
  public static class Mappings extends AlgorithmProvider {
    private static final String PREFIX = SipHash128.class.getName();
    
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("Mac.SIPHASH128-2-4", PREFIX + "$Mac24");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.Mac.SIPHASH128", "SIPHASH128-2-4");
      param1ConfigurableProvider.addAlgorithm("Mac.SIPHASH128-4-8", PREFIX + "$Mac48");
      param1ConfigurableProvider.addAlgorithm("KeyGenerator.SIPHASH128", PREFIX + "$KeyGen");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH128-2-4", "SIPHASH128");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH128-4-8", "SIPHASH128");
    }
  }
}
