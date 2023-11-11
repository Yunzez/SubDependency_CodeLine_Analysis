package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

public final class Zuc256Engine extends Zuc256CoreEngine {
  public Zuc256Engine() {}
  
  public Zuc256Engine(int paramInt) {
    super(paramInt);
  }
  
  private Zuc256Engine(Zuc256Engine paramZuc256Engine) {
    super(paramZuc256Engine);
  }
  
  public Memoable copy() {
    return new Zuc256Engine(this);
  }
}
