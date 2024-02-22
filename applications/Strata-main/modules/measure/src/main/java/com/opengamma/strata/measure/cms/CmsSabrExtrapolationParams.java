/*
 * Copyright (C) 2016 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.measure.cms;

import java.io.Serializable;
import java.lang.invoke.MethodHandles;

import org.joda.beans.ImmutableBean;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaBean;
import org.joda.beans.TypedMetaBean;
import org.joda.beans.gen.BeanDefinition;
import org.joda.beans.gen.PropertyDefinition;
import org.joda.beans.impl.light.LightMetaBean;

import com.opengamma.strata.calc.runner.CalculationParameter;
import com.opengamma.strata.measure.swaption.SwaptionMarketDataLookup;

/**
 * The additional parameters necessary for pricing CMS using SABR extrapolation replication.
 * <p>
 * The volatilities used in pricing are provided using {@link SwaptionMarketDataLookup}.
 */
@BeanDefinition(style = "light")
public final class CmsSabrExtrapolationParams
    implements CalculationParameter, ImmutableBean, Serializable {

  /**
   * The cut-off strike.
   * <p>
   * The smile is extrapolated above that level.
   */
  @PropertyDefinition
  private final double cutOffStrike;
  /**
   * The tail thickness parameter.
   * <p>
   * This must be greater than 0 in order to ensure that the call price converges to 0 for infinite strike.
   */
  @PropertyDefinition
  private final double mu;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance based on a lookup and market data.
   * <p>
   * The lookup knows how to obtain the volatilities from the market data.
   * This might involve accessing a surface or a cube.
   *
   * @param cutOffStrike  the cut-off strike
   * @param mu  the tail thickness parameter
   * @return the SABR extrapolation parameters
   */
  public static CmsSabrExtrapolationParams of(double cutOffStrike, double mu) {
    return new CmsSabrExtrapolationParams(cutOffStrike, mu);
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code CmsSabrExtrapolationParams}.
   */
  private static final TypedMetaBean<CmsSabrExtrapolationParams> META_BEAN =
      LightMetaBean.of(
          CmsSabrExtrapolationParams.class,
          MethodHandles.lookup(),
          new String[] {
              "cutOffStrike",
              "mu"},
          new Object[0]);

  /**
   * The meta-bean for {@code CmsSabrExtrapolationParams}.
   * @return the meta-bean, not null
   */
  public static TypedMetaBean<CmsSabrExtrapolationParams> meta() {
    return META_BEAN;
  }

  static {
    MetaBean.register(META_BEAN);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  private CmsSabrExtrapolationParams(
      double cutOffStrike,
      double mu) {
    this.cutOffStrike = cutOffStrike;
    this.mu = mu;
  }

  @Override
  public TypedMetaBean<CmsSabrExtrapolationParams> metaBean() {
    return META_BEAN;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the cut-off strike.
   * <p>
   * The smile is extrapolated above that level.
   * @return the value of the property
   */
  public double getCutOffStrike() {
    return cutOffStrike;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the tail thickness parameter.
   * <p>
   * This must be greater than 0 in order to ensure that the call price converges to 0 for infinite strike.
   * @return the value of the property
   */
  public double getMu() {
    return mu;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      CmsSabrExtrapolationParams other = (CmsSabrExtrapolationParams) obj;
      return JodaBeanUtils.equal(cutOffStrike, other.cutOffStrike) &&
          JodaBeanUtils.equal(mu, other.mu);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(cutOffStrike);
    hash = hash * 31 + JodaBeanUtils.hashCode(mu);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(96);
    buf.append("CmsSabrExtrapolationParams{");
    buf.append("cutOffStrike").append('=').append(JodaBeanUtils.toString(cutOffStrike)).append(',').append(' ');
    buf.append("mu").append('=').append(JodaBeanUtils.toString(mu));
    buf.append('}');
    return buf.toString();
  }

  //-------------------------- AUTOGENERATED END --------------------------
}