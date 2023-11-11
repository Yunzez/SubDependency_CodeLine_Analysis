package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.G3413CBCBlockCipher;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
import org.bouncycastle.crypto.modes.G3413OFBBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public class GOST3412_2015 {
  public static class CBC extends BaseBlockCipher {
    public CBC() {
      super(new G3413CBCBlockCipher(new GOST3412_2015Engine()), false, 128);
    }
  }
  
  public static class CTR extends BaseBlockCipher {
    public CTR() {
      super(new BufferedBlockCipher(new G3413CTRBlockCipher(new GOST3412_2015Engine())), true, 64);
    }
  }
  
  public static class ECB extends BaseBlockCipher {
    public ECB() {
      super(new GOST3412_2015Engine());
    }
  }
  
  public static class GCFB extends BaseBlockCipher {
    public GCFB() {
      super(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine())), false, 128);
    }
  }
  
  public static class GCFB8 extends BaseBlockCipher {
    public GCFB8() {
      super(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine(), 8)), false, 128);
    }
  }
  
  public static class KeyGen extends BaseKeyGenerator {
    public KeyGen() {
      this(256);
    }
    
    public KeyGen(int param1Int) {
      super("GOST3412-2015", param1Int, new CipherKeyGenerator());
    }
  }
  
  public static class Mac extends BaseMac {
    public Mac() {
      super(new CMac(new GOST3412_2015Engine()));
    }
  }
  
  public static class Mappings extends AlgorithmProvider {
    private static final String PREFIX = GOST3412_2015.class.getName();
    
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015", PREFIX + "$ECB");
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015/CFB", PREFIX + "$GCFB");
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015/CFB8", PREFIX + "$GCFB8");
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015/OFB", PREFIX + "$OFB");
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015/CBC", PREFIX + "$CBC");
      param1ConfigurableProvider.addAlgorithm("Cipher.GOST3412-2015/CTR", PREFIX + "$CTR");
      param1ConfigurableProvider.addAlgorithm("KeyGenerator.GOST3412-2015", PREFIX + "$KeyGen");
      param1ConfigurableProvider.addAlgorithm("Mac.GOST3412MAC", PREFIX + "$Mac");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.Mac.GOST3412-2015", "GOST3412MAC");
    }
  }
  
  public static class OFB extends BaseBlockCipher {
    public OFB() {
      super(new BufferedBlockCipher(new G3413OFBBlockCipher(new GOST3412_2015Engine())), false, 128);
    }
  }
}
