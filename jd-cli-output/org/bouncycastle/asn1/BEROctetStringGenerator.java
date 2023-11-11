package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

public class BEROctetStringGenerator extends BERGenerator {
  public BEROctetStringGenerator(OutputStream paramOutputStream) throws IOException {
    super(paramOutputStream);
    writeBERHeader(36);
  }
  
  public BEROctetStringGenerator(OutputStream paramOutputStream, int paramInt, boolean paramBoolean) throws IOException {
    super(paramOutputStream, paramInt, paramBoolean);
    writeBERHeader(36);
  }
  
  public OutputStream getOctetOutputStream() {
    return getOctetOutputStream(new byte[1000]);
  }
  
  public OutputStream getOctetOutputStream(byte[] paramArrayOfbyte) {
    return new BufferedBEROctetStream(paramArrayOfbyte);
  }
  
  private class BufferedBEROctetStream extends OutputStream {
    private byte[] _buf;
    
    private int _off;
    
    private DEROutputStream _derOut;
    
    BufferedBEROctetStream(byte[] param1ArrayOfbyte) {
      this._buf = param1ArrayOfbyte;
      this._off = 0;
      this._derOut = new DEROutputStream(BEROctetStringGenerator.this._out);
    }
    
    public void write(int param1Int) throws IOException {
      this._buf[this._off++] = (byte)param1Int;
      if (this._off == this._buf.length) {
        DEROctetString.encode(this._derOut, true, this._buf, 0, this._buf.length);
        this._off = 0;
      } 
    }
    
    public void write(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) throws IOException {
      int i = this._buf.length;
      int j = i - this._off;
      if (param1Int2 < j) {
        System.arraycopy(param1ArrayOfbyte, param1Int1, this._buf, this._off, param1Int2);
        this._off += param1Int2;
        return;
      } 
      int k = 0;
      if (this._off > 0) {
        System.arraycopy(param1ArrayOfbyte, param1Int1, this._buf, this._off, j);
        k += j;
        DEROctetString.encode(this._derOut, true, this._buf, 0, i);
      } 
      int m;
      while ((m = param1Int2 - k) >= i) {
        DEROctetString.encode(this._derOut, true, param1ArrayOfbyte, param1Int1 + k, i);
        k += i;
      } 
      System.arraycopy(param1ArrayOfbyte, param1Int1 + k, this._buf, 0, m);
      this._off = m;
    }
    
    public void close() throws IOException {
      if (this._off != 0)
        DEROctetString.encode(this._derOut, true, this._buf, 0, this._off); 
      this._derOut.flushInternal();
      BEROctetStringGenerator.this.writeBEREnd();
    }
  }
}
