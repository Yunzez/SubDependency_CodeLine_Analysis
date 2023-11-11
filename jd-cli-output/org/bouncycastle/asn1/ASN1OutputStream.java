package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

public class ASN1OutputStream {
  private OutputStream os;
  
  public static ASN1OutputStream create(OutputStream paramOutputStream) {
    return new ASN1OutputStream(paramOutputStream);
  }
  
  public static ASN1OutputStream create(OutputStream paramOutputStream, String paramString) {
    return paramString.equals("DER") ? new DEROutputStream(paramOutputStream) : (paramString.equals("DL") ? new DLOutputStream(paramOutputStream) : new ASN1OutputStream(paramOutputStream));
  }
  
  ASN1OutputStream(OutputStream paramOutputStream) {
    this.os = paramOutputStream;
  }
  
  public void close() throws IOException {
    this.os.close();
  }
  
  public void flush() throws IOException {
    this.os.flush();
  }
  
  public final void writeObject(ASN1Encodable paramASN1Encodable) throws IOException {
    if (null == paramASN1Encodable)
      throw new IOException("null object detected"); 
    writePrimitive(paramASN1Encodable.toASN1Primitive(), true);
    flushInternal();
  }
  
  public final void writeObject(ASN1Primitive paramASN1Primitive) throws IOException {
    if (null == paramASN1Primitive)
      throw new IOException("null object detected"); 
    writePrimitive(paramASN1Primitive, true);
    flushInternal();
  }
  
  void flushInternal() throws IOException {}
  
  DEROutputStream getDERSubStream() {
    return new DEROutputStream(this.os);
  }
  
  DLOutputStream getDLSubStream() {
    return new DLOutputStream(this.os);
  }
  
  final void writeDL(int paramInt) throws IOException {
    if (paramInt < 128) {
      write(paramInt);
    } else {
      byte[] arrayOfByte = new byte[5];
      int i = arrayOfByte.length;
      while (true) {
        arrayOfByte[--i] = (byte)paramInt;
        paramInt >>>= 8;
        if (paramInt == 0) {
          int j = arrayOfByte.length - i;
          arrayOfByte[--i] = (byte)(0x80 | j);
          write(arrayOfByte, i, j + 1);
          return;
        } 
      } 
    } 
  }
  
  final void write(int paramInt) throws IOException {
    this.os.write(paramInt);
  }
  
  final void write(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException {
    this.os.write(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  void writeElements(ASN1Encodable[] paramArrayOfASN1Encodable) throws IOException {
    byte b = 0;
    int i = paramArrayOfASN1Encodable.length;
    while (b < i) {
      paramArrayOfASN1Encodable[b].toASN1Primitive().encode(this, true);
      b++;
    } 
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt, byte paramByte) throws IOException {
    writeIdentifier(paramBoolean, paramInt);
    writeDL(1);
    write(paramByte);
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt, byte[] paramArrayOfbyte) throws IOException {
    writeIdentifier(paramBoolean, paramInt);
    writeDL(paramArrayOfbyte.length);
    write(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt1, byte[] paramArrayOfbyte, int paramInt2, int paramInt3) throws IOException {
    writeIdentifier(paramBoolean, paramInt1);
    writeDL(paramInt3);
    write(paramArrayOfbyte, paramInt2, paramInt3);
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt1, byte paramByte, byte[] paramArrayOfbyte, int paramInt2, int paramInt3) throws IOException {
    writeIdentifier(paramBoolean, paramInt1);
    writeDL(1 + paramInt3);
    write(paramByte);
    write(paramArrayOfbyte, paramInt2, paramInt3);
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt1, byte[] paramArrayOfbyte, int paramInt2, int paramInt3, byte paramByte) throws IOException {
    writeIdentifier(paramBoolean, paramInt1);
    writeDL(paramInt3 + 1);
    write(paramArrayOfbyte, paramInt2, paramInt3);
    write(paramByte);
  }
  
  final void writeEncodingDL(boolean paramBoolean, int paramInt1, int paramInt2, byte[] paramArrayOfbyte) throws IOException {
    writeIdentifier(paramBoolean, paramInt1, paramInt2);
    writeDL(paramArrayOfbyte.length);
    write(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  final void writeEncodingIL(boolean paramBoolean, int paramInt, ASN1Encodable[] paramArrayOfASN1Encodable) throws IOException {
    writeIdentifier(paramBoolean, paramInt);
    write(128);
    writeElements(paramArrayOfASN1Encodable);
    write(0);
    write(0);
  }
  
  final void writeIdentifier(boolean paramBoolean, int paramInt) throws IOException {
    if (paramBoolean)
      write(paramInt); 
  }
  
  final void writeIdentifier(boolean paramBoolean, int paramInt1, int paramInt2) throws IOException {
    if (paramBoolean)
      if (paramInt2 < 31) {
        write(paramInt1 | paramInt2);
      } else {
        byte[] arrayOfByte = new byte[6];
        int i = arrayOfByte.length;
        arrayOfByte[--i] = (byte)(paramInt2 & 0x7F);
        while (paramInt2 > 127) {
          paramInt2 >>>= 7;
          arrayOfByte[--i] = (byte)(paramInt2 & 0x7F | 0x80);
        } 
        arrayOfByte[--i] = (byte)(paramInt1 | 0x1F);
        write(arrayOfByte, i, arrayOfByte.length - i);
      }  
  }
  
  void writePrimitive(ASN1Primitive paramASN1Primitive, boolean paramBoolean) throws IOException {
    paramASN1Primitive.encode(this, paramBoolean);
  }
  
  void writePrimitives(ASN1Primitive[] paramArrayOfASN1Primitive) throws IOException {
    byte b = 0;
    int i = paramArrayOfASN1Primitive.length;
    while (b < i) {
      paramArrayOfASN1Primitive[b].encode(this, true);
      b++;
    } 
  }
  
  static int getLengthOfDL(int paramInt) {
    if (paramInt < 128)
      return 1; 
    byte b;
    for (b = 2; (paramInt >>>= 8) != 0; b++);
    return b;
  }
  
  static int getLengthOfEncodingDL(boolean paramBoolean, int paramInt) {
    return (paramBoolean ? 1 : 0) + getLengthOfDL(paramInt) + paramInt;
  }
  
  static int getLengthOfIdentifier(int paramInt) {
    if (paramInt < 31)
      return 1; 
    byte b;
    for (b = 2; (paramInt >>>= 7) != 0; b++);
    return b;
  }
}
