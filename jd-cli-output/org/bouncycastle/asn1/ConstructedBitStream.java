package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

class ConstructedBitStream extends InputStream {
  private final ASN1StreamParser _parser;
  
  private final boolean _octetAligned;
  
  private boolean _first = true;
  
  private int _padBits = 0;
  
  private ASN1BitStringParser _currentParser;
  
  private InputStream _currentStream;
  
  ConstructedBitStream(ASN1StreamParser paramASN1StreamParser, boolean paramBoolean) {
    this._parser = paramASN1StreamParser;
    this._octetAligned = paramBoolean;
  }
  
  int getPadBits() {
    return this._padBits;
  }
  
  public int read(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException {
    if (this._currentStream == null) {
      if (!this._first)
        return -1; 
      this._currentParser = getNextParser();
      if (this._currentParser == null)
        return -1; 
      this._first = false;
      this._currentStream = this._currentParser.getBitStream();
    } 
    int i = 0;
    while (true) {
      int j = this._currentStream.read(paramArrayOfbyte, paramInt1 + i, paramInt2 - i);
      if (j >= 0) {
        i += j;
        if (i == paramInt2)
          return i; 
        continue;
      } 
      this._padBits = this._currentParser.getPadBits();
      this._currentParser = getNextParser();
      if (this._currentParser == null) {
        this._currentStream = null;
        return (i < 1) ? -1 : i;
      } 
      this._currentStream = this._currentParser.getBitStream();
    } 
  }
  
  public int read() throws IOException {
    if (this._currentStream == null) {
      if (!this._first)
        return -1; 
      this._currentParser = getNextParser();
      if (this._currentParser == null)
        return -1; 
      this._first = false;
      this._currentStream = this._currentParser.getBitStream();
    } 
    while (true) {
      int i = this._currentStream.read();
      if (i >= 0)
        return i; 
      this._padBits = this._currentParser.getPadBits();
      this._currentParser = getNextParser();
      if (this._currentParser == null) {
        this._currentStream = null;
        return -1;
      } 
      this._currentStream = this._currentParser.getBitStream();
    } 
  }
  
  private ASN1BitStringParser getNextParser() throws IOException {
    ASN1Encodable aSN1Encodable = this._parser.readObject();
    if (aSN1Encodable == null) {
      if (this._octetAligned && this._padBits != 0)
        throw new IOException("expected octet-aligned bitstring, but found padBits: " + this._padBits); 
      return null;
    } 
    if (aSN1Encodable instanceof ASN1BitStringParser) {
      if (this._padBits != 0)
        throw new IOException("only the last nested bitstring can have padding"); 
      return (ASN1BitStringParser)aSN1Encodable;
    } 
    throw new IOException("unknown object encountered: " + aSN1Encodable.getClass());
  }
}
