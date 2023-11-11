package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public final class DERMacData {
  private final byte[] macData;
  
  private DERMacData(byte[] paramArrayOfbyte) {
    this.macData = paramArrayOfbyte;
  }
  
  public byte[] getMacData() {
    return Arrays.clone(this.macData);
  }
  
  public static final class Builder {
    private final DERMacData.Type type;
    
    private ASN1OctetString idU;
    
    private ASN1OctetString idV;
    
    private ASN1OctetString ephemDataU;
    
    private ASN1OctetString ephemDataV;
    
    private byte[] text;
    
    public Builder(DERMacData.Type param1Type, byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2, byte[] param1ArrayOfbyte3, byte[] param1ArrayOfbyte4) {
      this.type = param1Type;
      this.idU = DerUtil.getOctetString(param1ArrayOfbyte1);
      this.idV = DerUtil.getOctetString(param1ArrayOfbyte2);
      this.ephemDataU = DerUtil.getOctetString(param1ArrayOfbyte3);
      this.ephemDataV = DerUtil.getOctetString(param1ArrayOfbyte4);
    }
    
    public Builder withText(byte[] param1ArrayOfbyte) {
      this.text = DerUtil.toByteArray(new DERTaggedObject(false, 0, DerUtil.getOctetString(param1ArrayOfbyte)));
      return this;
    }
    
    public DERMacData build() {
      // Byte code:
      //   0: getstatic org/bouncycastle/crypto/util/DERMacData$1.$SwitchMap$org$bouncycastle$crypto$util$DERMacData$Type : [I
      //   3: aload_0
      //   4: getfield type : Lorg/bouncycastle/crypto/util/DERMacData$Type;
      //   7: invokevirtual ordinal : ()I
      //   10: iaload
      //   11: tableswitch default -> 144, 1 -> 40, 2 -> 40, 3 -> 92, 4 -> 92
      //   40: new org/bouncycastle/crypto/util/DERMacData
      //   43: dup
      //   44: aload_0
      //   45: aload_0
      //   46: getfield type : Lorg/bouncycastle/crypto/util/DERMacData$Type;
      //   49: invokevirtual getHeader : ()[B
      //   52: aload_0
      //   53: getfield idU : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   56: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   59: aload_0
      //   60: getfield idV : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   63: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   66: aload_0
      //   67: getfield ephemDataU : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   70: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   73: aload_0
      //   74: getfield ephemDataV : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   77: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   80: aload_0
      //   81: getfield text : [B
      //   84: invokespecial concatenate : ([B[B[B[B[B[B)[B
      //   87: aconst_null
      //   88: invokespecial <init> : ([BLorg/bouncycastle/crypto/util/DERMacData$1;)V
      //   91: areturn
      //   92: new org/bouncycastle/crypto/util/DERMacData
      //   95: dup
      //   96: aload_0
      //   97: aload_0
      //   98: getfield type : Lorg/bouncycastle/crypto/util/DERMacData$Type;
      //   101: invokevirtual getHeader : ()[B
      //   104: aload_0
      //   105: getfield idV : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   108: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   111: aload_0
      //   112: getfield idU : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   115: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   118: aload_0
      //   119: getfield ephemDataV : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   122: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   125: aload_0
      //   126: getfield ephemDataU : Lorg/bouncycastle/asn1/ASN1OctetString;
      //   129: invokestatic toByteArray : (Lorg/bouncycastle/asn1/ASN1Primitive;)[B
      //   132: aload_0
      //   133: getfield text : [B
      //   136: invokespecial concatenate : ([B[B[B[B[B[B)[B
      //   139: aconst_null
      //   140: invokespecial <init> : ([BLorg/bouncycastle/crypto/util/DERMacData$1;)V
      //   143: areturn
      //   144: new java/lang/IllegalStateException
      //   147: dup
      //   148: ldc 'Unknown type encountered in build'
      //   150: invokespecial <init> : (Ljava/lang/String;)V
      //   153: athrow
    }
    
    private byte[] concatenate(byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2, byte[] param1ArrayOfbyte3, byte[] param1ArrayOfbyte4, byte[] param1ArrayOfbyte5, byte[] param1ArrayOfbyte6) {
      return Arrays.concatenate(Arrays.concatenate(param1ArrayOfbyte1, param1ArrayOfbyte2, param1ArrayOfbyte3), Arrays.concatenate(param1ArrayOfbyte4, param1ArrayOfbyte5, param1ArrayOfbyte6));
    }
  }
  
  public enum Type {
    UNILATERALU("KC_1_U"),
    UNILATERALV("KC_1_V"),
    BILATERALU("KC_2_U"),
    BILATERALV("KC_2_V");
    
    private final String enc;
    
    Type(String param1String1) {
      this.enc = param1String1;
    }
    
    public byte[] getHeader() {
      return Strings.toByteArray(this.enc);
    }
  }
}
