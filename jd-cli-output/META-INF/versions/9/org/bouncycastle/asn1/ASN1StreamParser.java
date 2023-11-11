package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERApplicationSpecificParser;
import org.bouncycastle.asn1.BERBitStringParser;
import org.bouncycastle.asn1.BEROctetStringParser;
import org.bouncycastle.asn1.BERSequenceParser;
import org.bouncycastle.asn1.BERSetParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.DERExternalParser;
import org.bouncycastle.asn1.DEROctetStringParser;
import org.bouncycastle.asn1.DLBitStringParser;
import org.bouncycastle.asn1.DLSequenceParser;
import org.bouncycastle.asn1.DLSetParser;
import org.bouncycastle.asn1.DLTaggedObjectParser;
import org.bouncycastle.asn1.DefiniteLengthInputStream;
import org.bouncycastle.asn1.InMemoryRepresentable;
import org.bouncycastle.asn1.IndefiniteLengthInputStream;
import org.bouncycastle.asn1.StreamUtil;

public class ASN1StreamParser {
  private final InputStream _in;
  
  private final int _limit;
  
  private final byte[][] tmpBuffers;
  
  public ASN1StreamParser(InputStream paramInputStream) {
    this(paramInputStream, StreamUtil.findLimit(paramInputStream));
  }
  
  public ASN1StreamParser(byte[] paramArrayOfbyte) {
    this(new ByteArrayInputStream(paramArrayOfbyte), paramArrayOfbyte.length);
  }
  
  public ASN1StreamParser(InputStream paramInputStream, int paramInt) {
    this(paramInputStream, paramInt, new byte[11][]);
  }
  
  ASN1StreamParser(InputStream paramInputStream, int paramInt, byte[][] paramArrayOfbyte) {
    this._in = paramInputStream;
    this._limit = paramInt;
    this.tmpBuffers = paramArrayOfbyte;
  }
  
  public ASN1Encodable readObject() throws IOException {
    int i = this._in.read();
    if (i < 0)
      return null; 
    return implParseObject(i);
  }
  
  ASN1Encodable implParseObject(int paramInt) throws IOException {
    set00Check(false);
    int i = ASN1InputStream.readTagNumber(this._in, paramInt);
    int j = ASN1InputStream.readLength(this._in, this._limit, (i == 3 || i == 4 || i == 16 || i == 17 || i == 8));
    if (j < 0) {
      if (0 == (paramInt & 0x20))
        throw new IOException("indefinite-length primitive encoding encountered"); 
      IndefiniteLengthInputStream indefiniteLengthInputStream = new IndefiniteLengthInputStream(this._in, this._limit);
      org.bouncycastle.asn1.ASN1StreamParser aSN1StreamParser1 = new org.bouncycastle.asn1.ASN1StreamParser(indefiniteLengthInputStream, this._limit, this.tmpBuffers);
      int m = paramInt & 0xC0;
      if (0 != m) {
        if (64 == m)
          return new BERApplicationSpecificParser(i, aSN1StreamParser1); 
        return new BERTaggedObjectParser(m, i, aSN1StreamParser1);
      } 
      return aSN1StreamParser1.parseImplicitConstructedIL(i);
    } 
    DefiniteLengthInputStream definiteLengthInputStream = new DefiniteLengthInputStream(this._in, j, this._limit);
    if (0 == (paramInt & 0xE0))
      return parseImplicitPrimitive(i, definiteLengthInputStream); 
    org.bouncycastle.asn1.ASN1StreamParser aSN1StreamParser = new org.bouncycastle.asn1.ASN1StreamParser(definiteLengthInputStream, definiteLengthInputStream.getLimit(), this.tmpBuffers);
    int k = paramInt & 0xC0;
    if (0 != k) {
      boolean bool = ((paramInt & 0x20) != 0) ? true : false;
      if (64 == k)
        return aSN1StreamParser.loadTaggedDL(k, i, bool); 
      return new DLTaggedObjectParser(k, i, bool, aSN1StreamParser);
    } 
    return aSN1StreamParser.parseImplicitConstructedDL(i);
  }
  
  ASN1Primitive loadTaggedDL(int paramInt1, int paramInt2, boolean paramBoolean) throws IOException {
    if (!paramBoolean) {
      byte[] arrayOfByte = ((DefiniteLengthInputStream)this._in).toByteArray();
      return ASN1TaggedObject.createPrimitive(paramInt1, paramInt2, arrayOfByte);
    } 
    ASN1EncodableVector aSN1EncodableVector = readVector();
    return ASN1TaggedObject.createConstructedDL(paramInt1, paramInt2, aSN1EncodableVector);
  }
  
  ASN1Primitive loadTaggedIL(int paramInt1, int paramInt2) throws IOException {
    ASN1EncodableVector aSN1EncodableVector = readVector();
    return ASN1TaggedObject.createConstructedIL(paramInt1, paramInt2, aSN1EncodableVector);
  }
  
  ASN1Encodable parseImplicitConstructedDL(int paramInt) throws IOException {
    switch (paramInt) {
      case 3:
        return new BERBitStringParser(this);
      case 8:
        return new DERExternalParser(this);
      case 4:
        return new BEROctetStringParser(this);
      case 17:
        return new DLSetParser(this);
      case 16:
        return new DLSequenceParser(this);
    } 
    throw new ASN1Exception("unknown DL object encountered: 0x" + Integer.toHexString(paramInt));
  }
  
  ASN1Encodable parseImplicitConstructedIL(int paramInt) throws IOException {
    switch (paramInt) {
      case 3:
        return new BERBitStringParser(this);
      case 4:
        return new BEROctetStringParser(this);
      case 8:
        return new DERExternalParser(this);
      case 16:
        return new BERSequenceParser(this);
      case 17:
        return new BERSetParser(this);
    } 
    throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(paramInt));
  }
  
  ASN1Encodable parseImplicitPrimitive(int paramInt) throws IOException {
    return parseImplicitPrimitive(paramInt, (DefiniteLengthInputStream)this._in);
  }
  
  ASN1Encodable parseImplicitPrimitive(int paramInt, DefiniteLengthInputStream paramDefiniteLengthInputStream) throws IOException {
    switch (paramInt) {
      case 3:
        return new DLBitStringParser(paramDefiniteLengthInputStream);
      case 8:
        throw new ASN1Exception("externals must use constructed encoding (see X.690 8.18)");
      case 4:
        return new DEROctetStringParser(paramDefiniteLengthInputStream);
      case 17:
        throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
      case 16:
        throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
    } 
    try {
      return ASN1InputStream.createPrimitiveDERObject(paramInt, paramDefiniteLengthInputStream, this.tmpBuffers);
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new ASN1Exception("corrupted stream detected", illegalArgumentException);
    } 
  }
  
  ASN1Encodable parseObject(int paramInt) throws IOException {
    if (paramInt < 0 || paramInt > 30)
      throw new IllegalArgumentException("invalid universal tag number: " + paramInt); 
    int i = this._in.read();
    if (i < 0)
      return null; 
    if ((i & 0xFFFFFFDF) != paramInt)
      throw new IOException("unexpected identifier encountered: " + i); 
    return implParseObject(i);
  }
  
  ASN1TaggedObjectParser parseTaggedObject() throws IOException {
    int i = this._in.read();
    if (i < 0)
      return null; 
    int j = i & 0xC0;
    if (0 == j)
      throw new ASN1Exception("no tagged object found"); 
    return (ASN1TaggedObjectParser)implParseObject(i);
  }
  
  ASN1EncodableVector readVector() throws IOException {
    int i = this._in.read();
    if (i < 0)
      return new ASN1EncodableVector(0); 
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    while (true) {
      ASN1Encodable aSN1Encodable = implParseObject(i);
      if (aSN1Encodable instanceof InMemoryRepresentable) {
        aSN1EncodableVector.add(((InMemoryRepresentable)aSN1Encodable).getLoadedObject());
      } else {
        aSN1EncodableVector.add(aSN1Encodable.toASN1Primitive());
      } 
      if ((i = this._in.read()) < 0)
        return aSN1EncodableVector; 
    } 
  }
  
  private void set00Check(boolean paramBoolean) {
    if (this._in instanceof IndefiniteLengthInputStream)
      ((IndefiniteLengthInputStream)this._in).setEofOn00(paramBoolean); 
  }
}
