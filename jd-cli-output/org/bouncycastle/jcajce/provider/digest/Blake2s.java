package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

public class Blake2s {
  public static class Blake2s128 extends BCMessageDigest implements Cloneable {
    public Blake2s128() {
      super(new Blake2sDigest(128));
    }
    
    public Object clone() throws CloneNotSupportedException {
      Blake2s128 blake2s128 = (Blake2s128)super.clone();
      blake2s128.digest = new Blake2sDigest((Blake2sDigest)this.digest);
      return blake2s128;
    }
  }
  
  public static class Blake2s160 extends BCMessageDigest implements Cloneable {
    public Blake2s160() {
      super(new Blake2sDigest(160));
    }
    
    public Object clone() throws CloneNotSupportedException {
      Blake2s160 blake2s160 = (Blake2s160)super.clone();
      blake2s160.digest = new Blake2sDigest((Blake2sDigest)this.digest);
      return blake2s160;
    }
  }
  
  public static class Blake2s224 extends BCMessageDigest implements Cloneable {
    public Blake2s224() {
      super(new Blake2sDigest(224));
    }
    
    public Object clone() throws CloneNotSupportedException {
      Blake2s224 blake2s224 = (Blake2s224)super.clone();
      blake2s224.digest = new Blake2sDigest((Blake2sDigest)this.digest);
      return blake2s224;
    }
  }
  
  public static class Blake2s256 extends BCMessageDigest implements Cloneable {
    public Blake2s256() {
      super(new Blake2sDigest(256));
    }
    
    public Object clone() throws CloneNotSupportedException {
      Blake2s256 blake2s256 = (Blake2s256)super.clone();
      blake2s256.digest = new Blake2sDigest((Blake2sDigest)this.digest);
      return blake2s256;
    }
  }
  
  public static class Mappings extends DigestAlgorithmProvider {
    private static final String PREFIX = Blake2s.class.getName();
    
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("MessageDigest.BLAKE2S-256", PREFIX + "$Blake2s256");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s256, "BLAKE2S-256");
      param1ConfigurableProvider.addAlgorithm("MessageDigest.BLAKE2S-224", PREFIX + "$Blake2s224");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s224, "BLAKE2S-224");
      param1ConfigurableProvider.addAlgorithm("MessageDigest.BLAKE2S-160", PREFIX + "$Blake2s160");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s160, "BLAKE2S-160");
      param1ConfigurableProvider.addAlgorithm("MessageDigest.BLAKE2S-128", PREFIX + "$Blake2s128");
      param1ConfigurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s128, "BLAKE2S-128");
    }
  }
}
