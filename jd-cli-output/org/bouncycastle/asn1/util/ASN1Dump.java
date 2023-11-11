package org.bouncycastle.asn1.util;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1GraphicString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1NumericString;
import org.bouncycastle.asn1.ASN1ObjectDescriptor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.ASN1VideotexString;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class ASN1Dump {
  private static final String TAB = "    ";
  
  private static final int SAMPLE_SIZE = 32;
  
  static void _dumpAsString(String paramString, boolean paramBoolean, ASN1Primitive paramASN1Primitive, StringBuffer paramStringBuffer) {
    String str = Strings.lineSeparator();
    if (paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1Null) {
      paramStringBuffer.append(paramString);
      paramStringBuffer.append("NULL");
      paramStringBuffer.append(str);
    } else if (paramASN1Primitive instanceof ASN1Sequence) {
      paramStringBuffer.append(paramString);
      if (paramASN1Primitive instanceof org.bouncycastle.asn1.BERSequence) {
        paramStringBuffer.append("BER Sequence");
      } else if (paramASN1Primitive instanceof org.bouncycastle.asn1.DERSequence) {
        paramStringBuffer.append("DER Sequence");
      } else {
        paramStringBuffer.append("Sequence");
      } 
      paramStringBuffer.append(str);
      ASN1Sequence aSN1Sequence = (ASN1Sequence)paramASN1Primitive;
      String str1 = paramString + "    ";
      byte b = 0;
      int i = aSN1Sequence.size();
      while (b < i) {
        _dumpAsString(str1, paramBoolean, aSN1Sequence.getObjectAt(b).toASN1Primitive(), paramStringBuffer);
        b++;
      } 
    } else if (paramASN1Primitive instanceof ASN1Set) {
      paramStringBuffer.append(paramString);
      if (paramASN1Primitive instanceof org.bouncycastle.asn1.BERSet) {
        paramStringBuffer.append("BER Set");
      } else if (paramASN1Primitive instanceof org.bouncycastle.asn1.DERSet) {
        paramStringBuffer.append("DER Set");
      } else {
        paramStringBuffer.append("Set");
      } 
      paramStringBuffer.append(str);
      ASN1Set aSN1Set = (ASN1Set)paramASN1Primitive;
      String str1 = paramString + "    ";
      byte b = 0;
      int i = aSN1Set.size();
      while (b < i) {
        _dumpAsString(str1, paramBoolean, aSN1Set.getObjectAt(b).toASN1Primitive(), paramStringBuffer);
        b++;
      } 
    } else if (paramASN1Primitive instanceof ASN1ApplicationSpecific) {
      _dumpAsString(paramString, paramBoolean, ((ASN1ApplicationSpecific)paramASN1Primitive).getTaggedObject(), paramStringBuffer);
    } else if (paramASN1Primitive instanceof ASN1TaggedObject) {
      paramStringBuffer.append(paramString);
      if (paramASN1Primitive instanceof org.bouncycastle.asn1.BERTaggedObject) {
        paramStringBuffer.append("BER Tagged ");
      } else if (paramASN1Primitive instanceof org.bouncycastle.asn1.DERTaggedObject) {
        paramStringBuffer.append("DER Tagged ");
      } else {
        paramStringBuffer.append("Tagged ");
      } 
      ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject)paramASN1Primitive;
      paramStringBuffer.append(ASN1Util.getTagText(aSN1TaggedObject));
      if (!aSN1TaggedObject.isExplicit())
        paramStringBuffer.append(" IMPLICIT "); 
      paramStringBuffer.append(str);
      String str1 = paramString + "    ";
      _dumpAsString(str1, paramBoolean, aSN1TaggedObject.getBaseObject().toASN1Primitive(), paramStringBuffer);
    } else if (paramASN1Primitive instanceof ASN1OctetString) {
      ASN1OctetString aSN1OctetString = (ASN1OctetString)paramASN1Primitive;
      if (paramASN1Primitive instanceof org.bouncycastle.asn1.BEROctetString) {
        paramStringBuffer.append(paramString + "BER Constructed Octet String[" + (aSN1OctetString.getOctets()).length + "] ");
      } else {
        paramStringBuffer.append(paramString + "DER Octet String[" + (aSN1OctetString.getOctets()).length + "] ");
      } 
      if (paramBoolean) {
        paramStringBuffer.append(dumpBinaryDataAsString(paramString, aSN1OctetString.getOctets()));
      } else {
        paramStringBuffer.append(str);
      } 
    } else if (paramASN1Primitive instanceof ASN1ObjectIdentifier) {
      paramStringBuffer.append(paramString + "ObjectIdentifier(" + ((ASN1ObjectIdentifier)paramASN1Primitive).getId() + ")" + str);
    } else if (paramASN1Primitive instanceof ASN1RelativeOID) {
      paramStringBuffer.append(paramString + "RelativeOID(" + ((ASN1RelativeOID)paramASN1Primitive).getId() + ")" + str);
    } else if (paramASN1Primitive instanceof ASN1Boolean) {
      paramStringBuffer.append(paramString + "Boolean(" + ((ASN1Boolean)paramASN1Primitive).isTrue() + ")" + str);
    } else if (paramASN1Primitive instanceof ASN1Integer) {
      paramStringBuffer.append(paramString + "Integer(" + ((ASN1Integer)paramASN1Primitive).getValue() + ")" + str);
    } else if (paramASN1Primitive instanceof ASN1BitString) {
      ASN1BitString aSN1BitString = (ASN1BitString)paramASN1Primitive;
      byte[] arrayOfByte = aSN1BitString.getBytes();
      int i = aSN1BitString.getPadBits();
      if (aSN1BitString instanceof org.bouncycastle.asn1.DERBitString) {
        paramStringBuffer.append(paramString + "DER Bit String[" + arrayOfByte.length + ", " + i + "] ");
      } else if (aSN1BitString instanceof org.bouncycastle.asn1.DLBitString) {
        paramStringBuffer.append(paramString + "DL Bit String[" + arrayOfByte.length + ", " + i + "] ");
      } else {
        paramStringBuffer.append(paramString + "BER Bit String[" + arrayOfByte.length + ", " + i + "] ");
      } 
      if (paramBoolean) {
        paramStringBuffer.append(dumpBinaryDataAsString(paramString, arrayOfByte));
      } else {
        paramStringBuffer.append(str);
      } 
    } else if (paramASN1Primitive instanceof ASN1IA5String) {
      paramStringBuffer.append(paramString + "IA5String(" + ((ASN1IA5String)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1UTF8String) {
      paramStringBuffer.append(paramString + "UTF8String(" + ((ASN1UTF8String)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1NumericString) {
      paramStringBuffer.append(paramString + "NumericString(" + ((ASN1NumericString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1PrintableString) {
      paramStringBuffer.append(paramString + "PrintableString(" + ((ASN1PrintableString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1VisibleString) {
      paramStringBuffer.append(paramString + "VisibleString(" + ((ASN1VisibleString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1BMPString) {
      paramStringBuffer.append(paramString + "BMPString(" + ((ASN1BMPString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1T61String) {
      paramStringBuffer.append(paramString + "T61String(" + ((ASN1T61String)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1GraphicString) {
      paramStringBuffer.append(paramString + "GraphicString(" + ((ASN1GraphicString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1VideotexString) {
      paramStringBuffer.append(paramString + "VideotexString(" + ((ASN1VideotexString)paramASN1Primitive).getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1UTCTime) {
      paramStringBuffer.append(paramString + "UTCTime(" + ((ASN1UTCTime)paramASN1Primitive).getTime() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1GeneralizedTime) {
      paramStringBuffer.append(paramString + "GeneralizedTime(" + ((ASN1GeneralizedTime)paramASN1Primitive).getTime() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1Enumerated) {
      ASN1Enumerated aSN1Enumerated = (ASN1Enumerated)paramASN1Primitive;
      paramStringBuffer.append(paramString + "DER Enumerated(" + aSN1Enumerated.getValue() + ")" + str);
    } else if (paramASN1Primitive instanceof ASN1ObjectDescriptor) {
      ASN1ObjectDescriptor aSN1ObjectDescriptor = (ASN1ObjectDescriptor)paramASN1Primitive;
      paramStringBuffer.append(paramString + "ObjectDescriptor(" + aSN1ObjectDescriptor.getBaseGraphicString().getString() + ") " + str);
    } else if (paramASN1Primitive instanceof ASN1External) {
      ASN1External aSN1External = (ASN1External)paramASN1Primitive;
      paramStringBuffer.append(paramString + "External " + str);
      String str1 = paramString + "    ";
      if (aSN1External.getDirectReference() != null)
        paramStringBuffer.append(str1 + "Direct Reference: " + aSN1External.getDirectReference().getId() + str); 
      if (aSN1External.getIndirectReference() != null)
        paramStringBuffer.append(str1 + "Indirect Reference: " + aSN1External.getIndirectReference().toString() + str); 
      if (aSN1External.getDataValueDescriptor() != null)
        _dumpAsString(str1, paramBoolean, aSN1External.getDataValueDescriptor(), paramStringBuffer); 
      paramStringBuffer.append(str1 + "Encoding: " + aSN1External.getEncoding() + str);
      _dumpAsString(str1, paramBoolean, aSN1External.getExternalContent(), paramStringBuffer);
    } else {
      paramStringBuffer.append(paramString + paramASN1Primitive.toString() + str);
    } 
  }
  
  public static String dumpAsString(Object paramObject) {
    return dumpAsString(paramObject, false);
  }
  
  public static String dumpAsString(Object paramObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive;
    if (paramObject instanceof ASN1Primitive) {
      aSN1Primitive = (ASN1Primitive)paramObject;
    } else if (paramObject instanceof ASN1Encodable) {
      aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
    } else {
      return "unknown object type " + paramObject.toString();
    } 
    StringBuffer stringBuffer = new StringBuffer();
    _dumpAsString("", paramBoolean, aSN1Primitive, stringBuffer);
    return stringBuffer.toString();
  }
  
  private static String dumpBinaryDataAsString(String paramString, byte[] paramArrayOfbyte) {
    String str = Strings.lineSeparator();
    StringBuffer stringBuffer = new StringBuffer();
    paramString = paramString + "    ";
    stringBuffer.append(str);
    for (byte b = 0; b < paramArrayOfbyte.length; b += 32) {
      if (paramArrayOfbyte.length - b > 32) {
        stringBuffer.append(paramString);
        stringBuffer.append(Strings.fromByteArray(Hex.encode(paramArrayOfbyte, b, 32)));
        stringBuffer.append("    ");
        stringBuffer.append(calculateAscString(paramArrayOfbyte, b, 32));
        stringBuffer.append(str);
      } else {
        stringBuffer.append(paramString);
        stringBuffer.append(Strings.fromByteArray(Hex.encode(paramArrayOfbyte, b, paramArrayOfbyte.length - b)));
        for (int i = paramArrayOfbyte.length - b; i != 32; i++)
          stringBuffer.append("  "); 
        stringBuffer.append("    ");
        stringBuffer.append(calculateAscString(paramArrayOfbyte, b, paramArrayOfbyte.length - b));
        stringBuffer.append(str);
      } 
    } 
    return stringBuffer.toString();
  }
  
  private static String calculateAscString(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    StringBuffer stringBuffer = new StringBuffer();
    for (int i = paramInt1; i != paramInt1 + paramInt2; i++) {
      if (paramArrayOfbyte[i] >= 32 && paramArrayOfbyte[i] <= 126)
        stringBuffer.append((char)paramArrayOfbyte[i]); 
    } 
    return stringBuffer.toString();
  }
}
