/*
 * Copyright (C) 2016 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.measure.swaption;

import java.io.Serializable;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.joda.beans.ImmutableBean;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaBean;
import org.joda.beans.TypedMetaBean;
import org.joda.beans.gen.BeanDefinition;
import org.joda.beans.gen.PropertyDefinition;
import org.joda.beans.impl.light.LightMetaBean;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.opengamma.strata.basics.index.RateIndex;
import com.opengamma.strata.calc.CalculationRules;
import com.opengamma.strata.calc.runner.CalculationParameter;
import com.opengamma.strata.calc.runner.FunctionRequirements;
import com.opengamma.strata.collect.Messages;
import com.opengamma.strata.data.MarketData;
import com.opengamma.strata.data.MarketDataId;
import com.opengamma.strata.data.MarketDataNotFoundException;
import com.opengamma.strata.data.scenario.ScenarioMarketData;
import com.opengamma.strata.pricer.swaption.SwaptionVolatilities;
import com.opengamma.strata.pricer.swaption.SwaptionVolatilitiesId;

/**
 * The swaption lookup, used to select volatilities for pricing.
 * <p>
 * This provides swaption volatilities by index.
 * <p>
 * The lookup implements {@link CalculationParameter} and is used by passing it
 * as an argument to {@link CalculationRules}. It provides the link between the
 * data that the function needs and the data that is available in {@link ScenarioMarketData}.
 */
@BeanDefinition(style = "light")
final class DefaultSwaptionMarketDataLookup
    implements SwaptionMarketDataLookup, ImmutableBean, Serializable {

  /**
   * The volatility identifiers, keyed by index.
   */
  @PropertyDefinition(validate = "notNull")
  private final ImmutableMap<RateIndex, SwaptionVolatilitiesId> volatilityIds;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance based on a single mapping from index to volatility identifier.
   * <p>
   * The lookup provides volatilities for the specified index.
   *
   * @param index  the index
   * @param volatilityId  the volatility identifier
   * @return the swaption lookup containing the specified mapping
   */
  public static DefaultSwaptionMarketDataLookup of(RateIndex index, SwaptionVolatilitiesId volatilityId) {
    return new DefaultSwaptionMarketDataLookup(ImmutableMap.of(index, volatilityId));
  }

  /**
   * Obtains an instance based on a map of volatility identifiers.
   * <p>
   * The map is used to specify the appropriate volatilities to use for each index.
   *
   * @param volatilityIds  the volatility identifiers, keyed by index
   * @return the swaption lookup containing the specified volatilities
   */
  public static DefaultSwaptionMarketDataLookup of(Map<RateIndex, SwaptionVolatilitiesId> volatilityIds) {
    return new DefaultSwaptionMarketDataLookup(volatilityIds);
  }

  //-------------------------------------------------------------------------
  @Override
  public ImmutableSet<RateIndex> getVolatilityIndices() {
    return volatilityIds.keySet();
  }

  @Override
  public ImmutableSet<MarketDataId<?>> getVolatilityIds(RateIndex index) {
    SwaptionVolatilitiesId id = volatilityIds.get(index);
    if (id == null) {
      throw new IllegalArgumentException(msgIndexNotFound(index));
    }
    return ImmutableSet.of(id);
  }

  //-------------------------------------------------------------------------
  @Override
  public FunctionRequirements requirements(Set<RateIndex> indices) {
    ImmutableSet.Builder<SwaptionVolatilitiesId> requiredIndices = ImmutableSet.builder();
    for (RateIndex index : indices) {
      if (!volatilityIds.containsKey(index)) {
        throw new IllegalArgumentException(msgIndexNotFound(index));
      }
      requiredIndices.add(Objects.requireNonNull(volatilityIds.get(index)));
    }
    return FunctionRequirements.builder()
        .valueRequirements(requiredIndices.build())
        .build();
  }

  //-------------------------------------------------------------------------
  @Override
  public SwaptionVolatilities volatilities(RateIndex index, MarketData marketData) {
    SwaptionVolatilitiesId volatilityId = volatilityIds.get(index);
    if (volatilityId == null) {
      throw new MarketDataNotFoundException(msgIndexNotFound(index));
    }
    return marketData.getValue(volatilityId);
  }

  //-------------------------------------------------------------------------
  private String msgIndexNotFound(RateIndex index) {
    return Messages.format("Swaption lookup has no volatilities defined for index '{}'", index);
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code DefaultSwaptionMarketDataLookup}.
   */
  private static final TypedMetaBean<DefaultSwaptionMarketDataLookup> META_BEAN =
      LightMetaBean.of(
          DefaultSwaptionMarketDataLookup.class,
          MethodHandles.lookup(),
          new String[] {
              "volatilityIds"},
          ImmutableMap.of());

  /**
   * The meta-bean for {@code DefaultSwaptionMarketDataLookup}.
   * @return the meta-bean, not null
   */
  public static TypedMetaBean<DefaultSwaptionMarketDataLookup> meta() {
    return META_BEAN;
  }

  static {
    MetaBean.register(META_BEAN);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  private DefaultSwaptionMarketDataLookup(
      Map<RateIndex, SwaptionVolatilitiesId> volatilityIds) {
    JodaBeanUtils.notNull(volatilityIds, "volatilityIds");
    this.volatilityIds = ImmutableMap.copyOf(volatilityIds);
  }

  @Override
  public TypedMetaBean<DefaultSwaptionMarketDataLookup> metaBean() {
    return META_BEAN;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the volatility identifiers, keyed by index.
   * @return the value of the property, not null
   */
  public ImmutableMap<RateIndex, SwaptionVolatilitiesId> getVolatilityIds() {
    return volatilityIds;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      DefaultSwaptionMarketDataLookup other = (DefaultSwaptionMarketDataLookup) obj;
      return JodaBeanUtils.equal(volatilityIds, other.volatilityIds);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(volatilityIds);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(64);
    buf.append("DefaultSwaptionMarketDataLookup{");
    buf.append("volatilityIds").append('=').append(JodaBeanUtils.toString(volatilityIds));
    buf.append('}');
    return buf.toString();
  }

  //-------------------------- AUTOGENERATED END --------------------------
}
