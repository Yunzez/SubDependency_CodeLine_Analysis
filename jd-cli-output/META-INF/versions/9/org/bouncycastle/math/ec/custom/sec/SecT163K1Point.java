package META-INF.versions.9.org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class SecT163K1Point extends ECPoint.AbstractF2m {
  SecT163K1Point(ECCurve paramECCurve, ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    super(paramECCurve, paramECFieldElement1, paramECFieldElement2);
  }
  
  SecT163K1Point(ECCurve paramECCurve, ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    super(paramECCurve, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  protected ECPoint detach() {
    return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(null, getAffineXCoord(), getAffineYCoord());
  }
  
  public ECFieldElement getYCoord() {
    ECFieldElement eCFieldElement1 = this.x, eCFieldElement2 = this.y;
    if (isInfinity() || eCFieldElement1.isZero())
      return eCFieldElement2; 
    ECFieldElement eCFieldElement3 = eCFieldElement2.add(eCFieldElement1).multiply(eCFieldElement1);
    ECFieldElement eCFieldElement4 = this.zs[0];
    if (!eCFieldElement4.isOne())
      eCFieldElement3 = eCFieldElement3.divide(eCFieldElement4); 
    return eCFieldElement3;
  }
  
  protected boolean getCompressionYTilde() {
    ECFieldElement eCFieldElement1 = getRawXCoord();
    if (eCFieldElement1.isZero())
      return false; 
    ECFieldElement eCFieldElement2 = getRawYCoord();
    return (eCFieldElement2.testBitZero() != eCFieldElement1.testBitZero());
  }
  
  public ECPoint add(ECPoint paramECPoint) {
    ECFieldElement eCFieldElement13, eCFieldElement14, eCFieldElement15;
    if (isInfinity())
      return paramECPoint; 
    if (paramECPoint.isInfinity())
      return this; 
    ECCurve eCCurve = getCurve();
    ECFieldElement eCFieldElement1 = this.x;
    ECFieldElement eCFieldElement2 = paramECPoint.getRawXCoord();
    if (eCFieldElement1.isZero()) {
      if (eCFieldElement2.isZero())
        return eCCurve.getInfinity(); 
      return paramECPoint.add(this);
    } 
    ECFieldElement eCFieldElement3 = this.y, eCFieldElement4 = this.zs[0];
    ECFieldElement eCFieldElement5 = paramECPoint.getRawYCoord(), eCFieldElement6 = paramECPoint.getZCoord(0);
    boolean bool1 = eCFieldElement4.isOne();
    ECFieldElement eCFieldElement7 = eCFieldElement2, eCFieldElement8 = eCFieldElement5;
    if (!bool1) {
      eCFieldElement7 = eCFieldElement7.multiply(eCFieldElement4);
      eCFieldElement8 = eCFieldElement8.multiply(eCFieldElement4);
    } 
    boolean bool2 = eCFieldElement6.isOne();
    ECFieldElement eCFieldElement9 = eCFieldElement1, eCFieldElement10 = eCFieldElement3;
    if (!bool2) {
      eCFieldElement9 = eCFieldElement9.multiply(eCFieldElement6);
      eCFieldElement10 = eCFieldElement10.multiply(eCFieldElement6);
    } 
    ECFieldElement eCFieldElement11 = eCFieldElement10.add(eCFieldElement8);
    ECFieldElement eCFieldElement12 = eCFieldElement9.add(eCFieldElement7);
    if (eCFieldElement12.isZero()) {
      if (eCFieldElement11.isZero())
        return twice(); 
      return eCCurve.getInfinity();
    } 
    if (eCFieldElement2.isZero()) {
      ECPoint eCPoint = normalize();
      eCFieldElement1 = eCPoint.getXCoord();
      ECFieldElement eCFieldElement16 = eCPoint.getYCoord();
      ECFieldElement eCFieldElement17 = eCFieldElement5;
      ECFieldElement eCFieldElement18 = eCFieldElement16.add(eCFieldElement17).divide(eCFieldElement1);
      eCFieldElement13 = eCFieldElement18.square().add(eCFieldElement18).add(eCFieldElement1).addOne();
      if (eCFieldElement13.isZero())
        return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement13, eCCurve.getB()); 
      ECFieldElement eCFieldElement19 = eCFieldElement18.multiply(eCFieldElement1.add(eCFieldElement13)).add(eCFieldElement13).add(eCFieldElement16);
      eCFieldElement14 = eCFieldElement19.divide(eCFieldElement13).add(eCFieldElement13);
      eCFieldElement15 = eCCurve.fromBigInteger(ECConstants.ONE);
    } else {
      eCFieldElement12 = eCFieldElement12.square();
      ECFieldElement eCFieldElement16 = eCFieldElement11.multiply(eCFieldElement9);
      ECFieldElement eCFieldElement17 = eCFieldElement11.multiply(eCFieldElement7);
      eCFieldElement13 = eCFieldElement16.multiply(eCFieldElement17);
      if (eCFieldElement13.isZero())
        return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement13, eCCurve.getB()); 
      ECFieldElement eCFieldElement18 = eCFieldElement11.multiply(eCFieldElement12);
      if (!bool2)
        eCFieldElement18 = eCFieldElement18.multiply(eCFieldElement6); 
      eCFieldElement14 = eCFieldElement17.add(eCFieldElement12).squarePlusProduct(eCFieldElement18, eCFieldElement3.add(eCFieldElement4));
      eCFieldElement15 = eCFieldElement18;
      if (!bool1)
        eCFieldElement15 = eCFieldElement15.multiply(eCFieldElement4); 
    } 
    return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement13, eCFieldElement14, new ECFieldElement[] { eCFieldElement15 });
  }
  
  public ECPoint twice() {
    if (isInfinity())
      return this; 
    ECCurve eCCurve = getCurve();
    ECFieldElement eCFieldElement1 = this.x;
    if (eCFieldElement1.isZero())
      return eCCurve.getInfinity(); 
    ECFieldElement eCFieldElement2 = this.y, eCFieldElement3 = this.zs[0];
    boolean bool = eCFieldElement3.isOne();
    ECFieldElement eCFieldElement4 = bool ? eCFieldElement2 : eCFieldElement2.multiply(eCFieldElement3);
    ECFieldElement eCFieldElement5 = bool ? eCFieldElement3 : eCFieldElement3.square();
    ECFieldElement eCFieldElement6 = eCFieldElement2.square().add(eCFieldElement4).add(eCFieldElement5);
    if (eCFieldElement6.isZero())
      return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement6, eCCurve.getB()); 
    ECFieldElement eCFieldElement7 = eCFieldElement6.square();
    ECFieldElement eCFieldElement8 = bool ? eCFieldElement6 : eCFieldElement6.multiply(eCFieldElement5);
    ECFieldElement eCFieldElement9 = eCFieldElement2.add(eCFieldElement1).square();
    ECFieldElement eCFieldElement10 = eCFieldElement9.add(eCFieldElement6).add(eCFieldElement5).multiply(eCFieldElement9).add(eCFieldElement7);
    return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement7, eCFieldElement10, new ECFieldElement[] { eCFieldElement8 });
  }
  
  public ECPoint twicePlus(ECPoint paramECPoint) {
    if (isInfinity())
      return paramECPoint; 
    if (paramECPoint.isInfinity())
      return twice(); 
    ECCurve eCCurve = getCurve();
    ECFieldElement eCFieldElement1 = this.x;
    if (eCFieldElement1.isZero())
      return paramECPoint; 
    ECFieldElement eCFieldElement2 = paramECPoint.getRawXCoord(), eCFieldElement3 = paramECPoint.getZCoord(0);
    if (eCFieldElement2.isZero() || !eCFieldElement3.isOne())
      return twice().add(paramECPoint); 
    ECFieldElement eCFieldElement4 = this.y, eCFieldElement5 = this.zs[0];
    ECFieldElement eCFieldElement6 = paramECPoint.getRawYCoord();
    ECFieldElement eCFieldElement7 = eCFieldElement1.square();
    ECFieldElement eCFieldElement8 = eCFieldElement4.square();
    ECFieldElement eCFieldElement9 = eCFieldElement5.square();
    ECFieldElement eCFieldElement10 = eCFieldElement4.multiply(eCFieldElement5);
    ECFieldElement eCFieldElement11 = eCFieldElement9.add(eCFieldElement8).add(eCFieldElement10);
    ECFieldElement eCFieldElement12 = eCFieldElement6.multiply(eCFieldElement9).add(eCFieldElement8).multiplyPlusProduct(eCFieldElement11, eCFieldElement7, eCFieldElement9);
    ECFieldElement eCFieldElement13 = eCFieldElement2.multiply(eCFieldElement9);
    ECFieldElement eCFieldElement14 = eCFieldElement13.add(eCFieldElement11).square();
    if (eCFieldElement14.isZero()) {
      if (eCFieldElement12.isZero())
        return paramECPoint.twice(); 
      return eCCurve.getInfinity();
    } 
    if (eCFieldElement12.isZero())
      return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement12, eCCurve.getB()); 
    ECFieldElement eCFieldElement15 = eCFieldElement12.square().multiply(eCFieldElement13);
    ECFieldElement eCFieldElement16 = eCFieldElement12.multiply(eCFieldElement14).multiply(eCFieldElement9);
    ECFieldElement eCFieldElement17 = eCFieldElement12.add(eCFieldElement14).square().multiplyPlusProduct(eCFieldElement11, eCFieldElement6.addOne(), eCFieldElement16);
    return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(eCCurve, eCFieldElement15, eCFieldElement17, new ECFieldElement[] { eCFieldElement16 });
  }
  
  public ECPoint negate() {
    if (isInfinity())
      return this; 
    ECFieldElement eCFieldElement1 = this.x;
    if (eCFieldElement1.isZero())
      return this; 
    ECFieldElement eCFieldElement2 = this.y, eCFieldElement3 = this.zs[0];
    return new org.bouncycastle.math.ec.custom.sec.SecT163K1Point(this.curve, eCFieldElement1, eCFieldElement2.add(eCFieldElement3), new ECFieldElement[] { eCFieldElement3 });
  }
}
