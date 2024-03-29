/*
 * Copyright (C) 2015 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.product.swap;

import java.io.Serializable;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.Map;
import java.util.NoSuchElementException;

import org.joda.beans.Bean;
import org.joda.beans.ImmutableBean;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaBean;
import org.joda.beans.MetaProperty;
import org.joda.beans.gen.BeanDefinition;
import org.joda.beans.gen.ImmutableDefaults;
import org.joda.beans.gen.PropertyDefinition;
import org.joda.beans.impl.direct.DirectFieldsBeanBuilder;
import org.joda.beans.impl.direct.DirectMetaBean;
import org.joda.beans.impl.direct.DirectMetaProperty;
import org.joda.beans.impl.direct.DirectMetaPropertyMap;

import com.opengamma.strata.product.swap.type.FixedFloatSwapTemplate;

/**
 * A swap index implementation based on an immutable set of rules.
 * <p>
 * A standard immutable implementation of {@link SwapIndex} that defines the swap trade template,
 * including the swap convention and tenor.
 * <p>
 * In most cases, applications should refer to indices by name, using {@link SwapIndex#of(String)}.
 * The named index will typically be resolved to an instance of this class.
 * As such, it is recommended to use the {@code SwapIndex} interface in application
 * code rather than directly referring to this class.
 */
@BeanDefinition
public final class ImmutableSwapIndex
    implements SwapIndex, ImmutableBean, Serializable {

  /**
   * The index name.
   */
  @PropertyDefinition(validate = "notEmpty", overrideGet = true)
  private final String name;
  /**
   * Whether the index is active, defaulted to true.
   * <p>
   * Over time some indices become inactive and are no longer produced.
   * If this occurs, this flag will be set to false.
   */
  @PropertyDefinition(overrideGet = true)
  private final boolean active;
  /**
   * The fixing time.
   */
  @PropertyDefinition(validate = "notNull", overrideGet = true)
  private final LocalTime fixingTime;
  /**
   * The time-zone of the fixing time.
   */
  @PropertyDefinition(validate = "notNull", overrideGet = true)
  private final ZoneId fixingZone;
  /**
   * The template for creating a Fixed-Ibor or Fixed-Overnight swap.
   */
  @PropertyDefinition(validate = "notNull", overrideGet = true)
  private final FixedFloatSwapTemplate template;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance from the specified name, time and template.
   * 
   * @param name  the index name
   * @param fixingTime  the fixing time
   * @param fixingZone  the time-zone of the fixing time
   * @param template  the swap template
   * @return the index
   */
  public static ImmutableSwapIndex of(
      String name,
      LocalTime fixingTime,
      ZoneId fixingZone,
      FixedFloatSwapTemplate template) {

    return new ImmutableSwapIndex(name, true, fixingTime, fixingZone, template);
  }

  //-------------------------------------------------------------------------
  @ImmutableDefaults
  private static void applyDefaults(Builder builder) {
    builder.active = true;
  }

  //-------------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj instanceof ImmutableSwapIndex) {
      return name.equals(((ImmutableSwapIndex) obj).name);
    }
    return false;
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  //-------------------------------------------------------------------------
  /**
   * Returns the name of the index.
   * 
   * @return the name of the index
   */
  @Override
  public String toString() {
    return getName();
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code ImmutableSwapIndex}.
   * @return the meta-bean, not null
   */
  public static ImmutableSwapIndex.Meta meta() {
    return ImmutableSwapIndex.Meta.INSTANCE;
  }

  static {
    MetaBean.register(ImmutableSwapIndex.Meta.INSTANCE);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Returns a builder used to create an instance of the bean.
   * @return the builder, not null
   */
  public static ImmutableSwapIndex.Builder builder() {
    return new ImmutableSwapIndex.Builder();
  }

  private ImmutableSwapIndex(
      String name,
      boolean active,
      LocalTime fixingTime,
      ZoneId fixingZone,
      FixedFloatSwapTemplate template) {
    JodaBeanUtils.notEmpty(name, "name");
    JodaBeanUtils.notNull(fixingTime, "fixingTime");
    JodaBeanUtils.notNull(fixingZone, "fixingZone");
    JodaBeanUtils.notNull(template, "template");
    this.name = name;
    this.active = active;
    this.fixingTime = fixingTime;
    this.fixingZone = fixingZone;
    this.template = template;
  }

  @Override
  public ImmutableSwapIndex.Meta metaBean() {
    return ImmutableSwapIndex.Meta.INSTANCE;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the index name.
   * @return the value of the property, not empty
   */
  @Override
  public String getName() {
    return name;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets whether the index is active, defaulted to true.
   * <p>
   * Over time some indices become inactive and are no longer produced.
   * If this occurs, this flag will be set to false.
   * @return the value of the property
   */
  @Override
  public boolean isActive() {
    return active;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the fixing time.
   * @return the value of the property, not null
   */
  @Override
  public LocalTime getFixingTime() {
    return fixingTime;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the time-zone of the fixing time.
   * @return the value of the property, not null
   */
  @Override
  public ZoneId getFixingZone() {
    return fixingZone;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the template for creating a Fixed-Ibor or Fixed-Overnight swap.
   * @return the value of the property, not null
   */
  @Override
  public FixedFloatSwapTemplate getTemplate() {
    return template;
  }

  //-----------------------------------------------------------------------
  /**
   * Returns a builder that allows this bean to be mutated.
   * @return the mutable builder, not null
   */
  public Builder toBuilder() {
    return new Builder(this);
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code ImmutableSwapIndex}.
   */
  public static final class Meta extends DirectMetaBean {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-property for the {@code name} property.
     */
    private final MetaProperty<String> name = DirectMetaProperty.ofImmutable(
        this, "name", ImmutableSwapIndex.class, String.class);
    /**
     * The meta-property for the {@code active} property.
     */
    private final MetaProperty<Boolean> active = DirectMetaProperty.ofImmutable(
        this, "active", ImmutableSwapIndex.class, Boolean.TYPE);
    /**
     * The meta-property for the {@code fixingTime} property.
     */
    private final MetaProperty<LocalTime> fixingTime = DirectMetaProperty.ofImmutable(
        this, "fixingTime", ImmutableSwapIndex.class, LocalTime.class);
    /**
     * The meta-property for the {@code fixingZone} property.
     */
    private final MetaProperty<ZoneId> fixingZone = DirectMetaProperty.ofImmutable(
        this, "fixingZone", ImmutableSwapIndex.class, ZoneId.class);
    /**
     * The meta-property for the {@code template} property.
     */
    private final MetaProperty<FixedFloatSwapTemplate> template = DirectMetaProperty.ofImmutable(
        this, "template", ImmutableSwapIndex.class, FixedFloatSwapTemplate.class);
    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> metaPropertyMap$ = new DirectMetaPropertyMap(
        this, null,
        "name",
        "active",
        "fixingTime",
        "fixingZone",
        "template");

    /**
     * Restricted constructor.
     */
    private Meta() {
    }

    @Override
    protected MetaProperty<?> metaPropertyGet(String propertyName) {
      switch (propertyName.hashCode()) {
        case 3373707:  // name
          return name;
        case -1422950650:  // active
          return active;
        case 1255686170:  // fixingTime
          return fixingTime;
        case 1255870713:  // fixingZone
          return fixingZone;
        case -1321546630:  // template
          return template;
      }
      return super.metaPropertyGet(propertyName);
    }

    @Override
    public ImmutableSwapIndex.Builder builder() {
      return new ImmutableSwapIndex.Builder();
    }

    @Override
    public Class<? extends ImmutableSwapIndex> beanType() {
      return ImmutableSwapIndex.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
    /**
     * The meta-property for the {@code name} property.
     * @return the meta-property, not null
     */
    public MetaProperty<String> name() {
      return name;
    }

    /**
     * The meta-property for the {@code active} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Boolean> active() {
      return active;
    }

    /**
     * The meta-property for the {@code fixingTime} property.
     * @return the meta-property, not null
     */
    public MetaProperty<LocalTime> fixingTime() {
      return fixingTime;
    }

    /**
     * The meta-property for the {@code fixingZone} property.
     * @return the meta-property, not null
     */
    public MetaProperty<ZoneId> fixingZone() {
      return fixingZone;
    }

    /**
     * The meta-property for the {@code template} property.
     * @return the meta-property, not null
     */
    public MetaProperty<FixedFloatSwapTemplate> template() {
      return template;
    }

    //-----------------------------------------------------------------------
    @Override
    protected Object propertyGet(Bean bean, String propertyName, boolean quiet) {
      switch (propertyName.hashCode()) {
        case 3373707:  // name
          return ((ImmutableSwapIndex) bean).getName();
        case -1422950650:  // active
          return ((ImmutableSwapIndex) bean).isActive();
        case 1255686170:  // fixingTime
          return ((ImmutableSwapIndex) bean).getFixingTime();
        case 1255870713:  // fixingZone
          return ((ImmutableSwapIndex) bean).getFixingZone();
        case -1321546630:  // template
          return ((ImmutableSwapIndex) bean).getTemplate();
      }
      return super.propertyGet(bean, propertyName, quiet);
    }

    @Override
    protected void propertySet(Bean bean, String propertyName, Object newValue, boolean quiet) {
      metaProperty(propertyName);
      if (quiet) {
        return;
      }
      throw new UnsupportedOperationException("Property cannot be written: " + propertyName);
    }

  }

  //-----------------------------------------------------------------------
  /**
   * The bean-builder for {@code ImmutableSwapIndex}.
   */
  public static final class Builder extends DirectFieldsBeanBuilder<ImmutableSwapIndex> {

    private String name;
    private boolean active;
    private LocalTime fixingTime;
    private ZoneId fixingZone;
    private FixedFloatSwapTemplate template;

    /**
     * Restricted constructor.
     */
    private Builder() {
      applyDefaults(this);
    }

    /**
     * Restricted copy constructor.
     * @param beanToCopy  the bean to copy from, not null
     */
    private Builder(ImmutableSwapIndex beanToCopy) {
      this.name = beanToCopy.getName();
      this.active = beanToCopy.isActive();
      this.fixingTime = beanToCopy.getFixingTime();
      this.fixingZone = beanToCopy.getFixingZone();
      this.template = beanToCopy.getTemplate();
    }

    //-----------------------------------------------------------------------
    @Override
    public Object get(String propertyName) {
      switch (propertyName.hashCode()) {
        case 3373707:  // name
          return name;
        case -1422950650:  // active
          return active;
        case 1255686170:  // fixingTime
          return fixingTime;
        case 1255870713:  // fixingZone
          return fixingZone;
        case -1321546630:  // template
          return template;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
    }

    @Override
    public Builder set(String propertyName, Object newValue) {
      switch (propertyName.hashCode()) {
        case 3373707:  // name
          this.name = (String) newValue;
          break;
        case -1422950650:  // active
          this.active = (Boolean) newValue;
          break;
        case 1255686170:  // fixingTime
          this.fixingTime = (LocalTime) newValue;
          break;
        case 1255870713:  // fixingZone
          this.fixingZone = (ZoneId) newValue;
          break;
        case -1321546630:  // template
          this.template = (FixedFloatSwapTemplate) newValue;
          break;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
      return this;
    }

    @Override
    public Builder set(MetaProperty<?> property, Object value) {
      super.set(property, value);
      return this;
    }

    @Override
    public ImmutableSwapIndex build() {
      return new ImmutableSwapIndex(
          name,
          active,
          fixingTime,
          fixingZone,
          template);
    }

    //-----------------------------------------------------------------------
    /**
     * Sets the index name.
     * @param name  the new value, not empty
     * @return this, for chaining, not null
     */
    public Builder name(String name) {
      JodaBeanUtils.notEmpty(name, "name");
      this.name = name;
      return this;
    }

    /**
     * Sets whether the index is active, defaulted to true.
     * <p>
     * Over time some indices become inactive and are no longer produced.
     * If this occurs, this flag will be set to false.
     * @param active  the new value
     * @return this, for chaining, not null
     */
    public Builder active(boolean active) {
      this.active = active;
      return this;
    }

    /**
     * Sets the fixing time.
     * @param fixingTime  the new value, not null
     * @return this, for chaining, not null
     */
    public Builder fixingTime(LocalTime fixingTime) {
      JodaBeanUtils.notNull(fixingTime, "fixingTime");
      this.fixingTime = fixingTime;
      return this;
    }

    /**
     * Sets the time-zone of the fixing time.
     * @param fixingZone  the new value, not null
     * @return this, for chaining, not null
     */
    public Builder fixingZone(ZoneId fixingZone) {
      JodaBeanUtils.notNull(fixingZone, "fixingZone");
      this.fixingZone = fixingZone;
      return this;
    }

    /**
     * Sets the template for creating a Fixed-Ibor or Fixed-Overnight swap.
     * @param template  the new value, not null
     * @return this, for chaining, not null
     */
    public Builder template(FixedFloatSwapTemplate template) {
      JodaBeanUtils.notNull(template, "template");
      this.template = template;
      return this;
    }

    //-----------------------------------------------------------------------
    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder(192);
      buf.append("ImmutableSwapIndex.Builder{");
      buf.append("name").append('=').append(JodaBeanUtils.toString(name)).append(',').append(' ');
      buf.append("active").append('=').append(JodaBeanUtils.toString(active)).append(',').append(' ');
      buf.append("fixingTime").append('=').append(JodaBeanUtils.toString(fixingTime)).append(',').append(' ');
      buf.append("fixingZone").append('=').append(JodaBeanUtils.toString(fixingZone)).append(',').append(' ');
      buf.append("template").append('=').append(JodaBeanUtils.toString(template));
      buf.append('}');
      return buf.toString();
    }

  }

  //-------------------------- AUTOGENERATED END --------------------------
}
