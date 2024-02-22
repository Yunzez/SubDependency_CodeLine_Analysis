/*
 * Copyright (C) 2012 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.pricer.impl.option;

import java.io.Serializable;
import java.lang.invoke.MethodHandles;

import org.joda.beans.ImmutableBean;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaBean;
import org.joda.beans.TypedMetaBean;
import org.joda.beans.gen.BeanDefinition;
import org.joda.beans.gen.PropertyDefinition;
import org.joda.beans.impl.light.LightMetaBean;

/**
 * A data bundle with the data require for the normal option model (Bachelier model).
 */
@BeanDefinition(style = "light")
public final class NormalFunctionData
    implements ImmutableBean, Serializable {
  // this class has been replaced by NormalFormulaRepository
  // it is retained for testing purposes

  /**
   * The forward value of the underlying asset
   * For example, the forward value of a stock, or the forward Libor rate.
   */
  @PropertyDefinition
  private final double forward;
  /**
   * The numeraire associated with the equation.
   */
  @PropertyDefinition
  private final double numeraire;
  /**
   * The normal volatility (sigma).
   */
  @PropertyDefinition
  private final double normalVolatility;

  //-------------------------------------------------------------------------
  /**
   * Data bundle for pricing in a normal framework.
   * That is, the forward value of the underlying asset is a martingale in the chosen numeraire measure.
   * 
   * @param forward  the forward value of the underlying asset, such as forward value of a stock, or forward Libor rate
   * @param numeraire  the numeraire associated with the equation
   * @param normalVolatility  the normal volatility (sigma)
   * @return the function data
   */
  public static NormalFunctionData of(double forward, double numeraire, double normalVolatility) {
    return new NormalFunctionData(forward, numeraire, normalVolatility);
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code NormalFunctionData}.
   */
  private static final TypedMetaBean<NormalFunctionData> META_BEAN =
      LightMetaBean.of(
          NormalFunctionData.class,
          MethodHandles.lookup(),
          new String[] {
              "forward",
              "numeraire",
              "normalVolatility"},
          new Object[0]);

  /**
   * The meta-bean for {@code NormalFunctionData}.
   * @return the meta-bean, not null
   */
  public static TypedMetaBean<NormalFunctionData> meta() {
    return META_BEAN;
  }

  static {
    MetaBean.register(META_BEAN);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  private NormalFunctionData(
      double forward,
      double numeraire,
      double normalVolatility) {
    this.forward = forward;
    this.numeraire = numeraire;
    this.normalVolatility = normalVolatility;
  }

  @Override
  public TypedMetaBean<NormalFunctionData> metaBean() {
    return META_BEAN;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the forward value of the underlying asset
   * For example, the forward value of a stock, or the forward Libor rate.
   * @return the value of the property
   */
  public double getForward() {
    return forward;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the numeraire associated with the equation.
   * @return the value of the property
   */
  public double getNumeraire() {
    return numeraire;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the normal volatility (sigma).
   * @return the value of the property
   */
  public double getNormalVolatility() {
    return normalVolatility;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      NormalFunctionData other = (NormalFunctionData) obj;
      return JodaBeanUtils.equal(forward, other.forward) &&
          JodaBeanUtils.equal(numeraire, other.numeraire) &&
          JodaBeanUtils.equal(normalVolatility, other.normalVolatility);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(forward);
    hash = hash * 31 + JodaBeanUtils.hashCode(numeraire);
    hash = hash * 31 + JodaBeanUtils.hashCode(normalVolatility);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(128);
    buf.append("NormalFunctionData{");
    buf.append("forward").append('=').append(JodaBeanUtils.toString(forward)).append(',').append(' ');
    buf.append("numeraire").append('=').append(JodaBeanUtils.toString(numeraire)).append(',').append(' ');
    buf.append("normalVolatility").append('=').append(JodaBeanUtils.toString(normalVolatility));
    buf.append('}');
    return buf.toString();
  }

  //-------------------------- AUTOGENERATED END --------------------------
}