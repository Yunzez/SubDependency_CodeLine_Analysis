package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.LimitedInputStream;
import org.bouncycastle.util.io.Streams;

class DefiniteLengthInputStream extends LimitedInputStream {
  private static final byte[] EMPTY_BYTES = new byte[0];
  
  private final int _originalLength;
  
  private int _remaining;
  
  DefiniteLengthInputStream(InputStream paramInputStream, int paramInt1, int paramInt2) {
    super(paramInputStream, paramInt2);
    if (paramInt1 <= 0) {
      if (paramInt1 < 0)
        throw new IllegalArgumentException("negative lengths not allowed"); 
      setParentEofDetect(true);
    } 
    this._originalLength = paramInt1;
    this._remaining = paramInt1;
  }
  
  int getRemaining() {
    return this._remaining;
  }
  
  public int read() throws IOException {
    if (this._remaining == 0)
      return -1; 
    int i = this._in.read();
    if (i < 0)
      throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining); 
    if (--this._remaining == 0)
      setParentEofDetect(true); 
    return i;
  }
  
  public int read(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException {
    if (this._remaining == 0)
      return -1; 
    int i = Math.min(paramInt2, this._remaining);
    int j = this._in.read(paramArrayOfbyte, paramInt1, i);
    if (j < 0)
      throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining); 
    if ((this._remaining -= j) == 0)
      setParentEofDetect(true); 
    return j;
  }
  
  void readAllIntoByteArray(byte[] paramArrayOfbyte) throws IOException {
    if (this._remaining != paramArrayOfbyte.length)
      throw new IllegalArgumentException("buffer length not right for data"); 
    if (this._remaining == 0)
      return; 
    int i = getLimit();
    if (this._remaining >= i)
      throw new IOException("corrupted stream - out of bounds length found: " + this._remaining + " >= " + i); 
    if ((this._remaining -= Streams.readFully(this._in, paramArrayOfbyte, 0, paramArrayOfbyte.length)) != 0)
      throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining); 
    setParentEofDetect(true);
  }
  
  byte[] toByteArray() throws IOException {
    if (this._remaining == 0)
      return EMPTY_BYTES; 
    int i = getLimit();
    if (this._remaining >= i)
      throw new IOException("corrupted stream - out of bounds length found: " + this._remaining + " >= " + i); 
    byte[] arrayOfByte = new byte[this._remaining];
    if ((this._remaining -= Streams.readFully(this._in, arrayOfByte, 0, arrayOfByte.length)) != 0)
      throw new EOFException("DEF length " + this._originalLength + " object truncated by " + this._remaining); 
    setParentEofDetect(true);
    return arrayOfByte;
  }
}
