package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

public final class Zuc128Engine extends Zuc128CoreEngine {
  public Zuc128Engine() {}
  
  private Zuc128Engine(Zuc128Engine paramZuc128Engine) {
    super(paramZuc128Engine);
  }
  
  public Memoable copy() {
    return new Zuc128Engine(this);
  }
}
