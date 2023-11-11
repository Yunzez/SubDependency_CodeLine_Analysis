package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

public class BEROctetString extends ASN1OctetString {
  private static final int DEFAULT_SEGMENT_LIMIT = 1000;
  
  private final int segmentLimit;
  
  private final ASN1OctetString[] elements;
  
  static byte[] flattenOctetStrings(ASN1OctetString[] paramArrayOfASN1OctetString) {
    int i = paramArrayOfASN1OctetString.length;
    switch (i) {
      case 0:
        return EMPTY_OCTETS;
      case 1:
        return (paramArrayOfASN1OctetString[0]).string;
    } 
    int j = 0;
    for (byte b1 = 0; b1 < i; b1++)
      j += (paramArrayOfASN1OctetString[b1]).string.length; 
    byte[] arrayOfByte = new byte[j];
    byte b2 = 0;
    int k = 0;
    while (b2 < i) {
      byte[] arrayOfByte1 = (paramArrayOfASN1OctetString[b2]).string;
      System.arraycopy(arrayOfByte1, 0, arrayOfByte, k, arrayOfByte1.length);
      k += arrayOfByte1.length;
      b2++;
    } 
    return arrayOfByte;
  }
  
  public BEROctetString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, 1000);
  }
  
  public BEROctetString(ASN1OctetString[] paramArrayOfASN1OctetString) {
    this(paramArrayOfASN1OctetString, 1000);
  }
  
  public BEROctetString(byte[] paramArrayOfbyte, int paramInt) {
    this(paramArrayOfbyte, (ASN1OctetString[])null, paramInt);
  }
  
  public BEROctetString(ASN1OctetString[] paramArrayOfASN1OctetString, int paramInt) {
    this(flattenOctetStrings(paramArrayOfASN1OctetString), paramArrayOfASN1OctetString, paramInt);
  }
  
  private BEROctetString(byte[] paramArrayOfbyte, ASN1OctetString[] paramArrayOfASN1OctetString, int paramInt) {
    super(paramArrayOfbyte);
    this.elements = paramArrayOfASN1OctetString;
    this.segmentLimit = paramInt;
  }
  
  public Enumeration getObjects() {
    return (this.elements == null) ? new Enumeration() {
        int pos = 0;
        
        public boolean hasMoreElements() {
          return (this.pos < BEROctetString.this.string.length);
        }
        
        public Object nextElement() {
          if (this.pos < BEROctetString.this.string.length) {
            int i = Math.min(BEROctetString.this.string.length - this.pos, BEROctetString.this.segmentLimit);
            byte[] arrayOfByte = new byte[i];
            System.arraycopy(BEROctetString.this.string, this.pos, arrayOfByte, 0, i);
            this.pos += i;
            return new DEROctetString(arrayOfByte);
          } 
          throw new NoSuchElementException();
        }
      } : new Enumeration() {
        int counter = 0;
        
        public boolean hasMoreElements() {
          return (this.counter < BEROctetString.this.elements.length);
        }
        
        public Object nextElement() {
          if (this.counter < BEROctetString.this.elements.length)
            return BEROctetString.this.elements[this.counter++]; 
          throw new NoSuchElementException();
        }
      };
  }
  
  boolean encodeConstructed() {
    return (null != this.elements || this.string.length > this.segmentLimit);
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    if (!encodeConstructed())
      return DEROctetString.encodedLength(paramBoolean, this.string.length); 
    int i = paramBoolean ? 4 : 3;
    if (null != this.elements) {
      for (byte b = 0; b < this.elements.length; b++)
        i += this.elements[b].encodedLength(true); 
    } else {
      int j = this.string.length / this.segmentLimit;
      i += j * DEROctetString.encodedLength(true, this.segmentLimit);
      int k = this.string.length - j * this.segmentLimit;
      if (k > 0)
        i += DEROctetString.encodedLength(true, k); 
    } 
    return i;
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    if (!encodeConstructed()) {
      DEROctetString.encode(paramASN1OutputStream, paramBoolean, this.string, 0, this.string.length);
      return;
    } 
    paramASN1OutputStream.writeIdentifier(paramBoolean, 36);
    paramASN1OutputStream.write(128);
    if (null != this.elements) {
      paramASN1OutputStream.writePrimitives((ASN1Primitive[])this.elements);
    } else {
      for (int i = 0; i < this.string.length; i += j) {
        int j = Math.min(this.string.length - i, this.segmentLimit);
        DEROctetString.encode(paramASN1OutputStream, true, this.string, i, j);
      } 
    } 
    paramASN1OutputStream.write(0);
    paramASN1OutputStream.write(0);
  }
}
