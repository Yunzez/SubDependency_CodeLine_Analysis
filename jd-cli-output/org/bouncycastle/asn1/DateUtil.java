package org.bouncycastle.asn1;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

class DateUtil {
  private static Long ZERO = longValueOf(0L);
  
  private static final Map localeCache = new HashMap<Object, Object>();
  
  static Locale EN_Locale = forEN();
  
  private static Locale forEN() {
    if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage()))
      return Locale.getDefault(); 
    Locale[] arrayOfLocale = Locale.getAvailableLocales();
    for (byte b = 0; b != arrayOfLocale.length; b++) {
      if ("en".equalsIgnoreCase(arrayOfLocale[b].getLanguage()))
        return arrayOfLocale[b]; 
    } 
    return Locale.getDefault();
  }
  
  static Date epochAdjust(Date paramDate) throws ParseException {
    Locale locale = Locale.getDefault();
    if (locale == null)
      return paramDate; 
    synchronized (localeCache) {
      Long long_ = (Long)localeCache.get(locale);
      if (long_ == null) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");
        long l = simpleDateFormat.parse("19700101000000GMT+00:00").getTime();
        if (l == 0L) {
          long_ = ZERO;
        } else {
          long_ = longValueOf(l);
        } 
        localeCache.put(locale, long_);
      } 
      if (long_ != ZERO)
        return new Date(paramDate.getTime() - long_.longValue()); 
      return paramDate;
    } 
  }
  
  private static Long longValueOf(long paramLong) {
    return Long.valueOf(paramLong);
  }
}
