package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XMSSMTKeyParameters extends AsymmetricKeyParameter {
  private final String treeDigest;
  
  public XMSSMTKeyParameters(boolean paramBoolean, String paramString) {
    super(paramBoolean);
    this.treeDigest = paramString;
  }
  
  public String getTreeDigest() {
    return this.treeDigest;
  }
}
