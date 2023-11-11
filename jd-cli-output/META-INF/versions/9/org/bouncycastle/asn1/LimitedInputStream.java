package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.InputStream;
import org.bouncycastle.asn1.IndefiniteLengthInputStream;

abstract class LimitedInputStream extends InputStream {
  protected final InputStream _in;
  
  private int _limit;
  
  LimitedInputStream(InputStream paramInputStream, int paramInt) {
    this._in = paramInputStream;
    this._limit = paramInt;
  }
  
  int getLimit() {
    return this._limit;
  }
  
  protected void setParentEofDetect(boolean paramBoolean) {
    if (this._in instanceof IndefiniteLengthInputStream)
      ((IndefiniteLengthInputStream)this._in).setEofOn00(paramBoolean); 
  }
}
