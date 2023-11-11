package META-INF.versions.9.org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.x9.X9ECParameters;

public abstract class X9ECParametersHolder {
  private X9ECParameters params;
  
  public synchronized X9ECParameters getParameters() {
    if (this.params == null)
      this.params = createParameters(); 
    return this.params;
  }
  
  protected abstract X9ECParameters createParameters();
}
