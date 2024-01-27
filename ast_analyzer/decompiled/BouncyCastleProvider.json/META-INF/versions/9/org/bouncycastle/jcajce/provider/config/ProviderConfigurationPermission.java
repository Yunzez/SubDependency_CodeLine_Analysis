package META-INF.versions.9.org.bouncycastle.jcajce.provider.config;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.StringTokenizer;
import org.bouncycastle.util.Strings;

public class ProviderConfigurationPermission extends BasicPermission {
  private static final int THREAD_LOCAL_EC_IMPLICITLY_CA = 1;
  
  private static final int EC_IMPLICITLY_CA = 2;
  
  private static final int THREAD_LOCAL_DH_DEFAULT_PARAMS = 4;
  
  private static final int DH_DEFAULT_PARAMS = 8;
  
  private static final int ACCEPTABLE_EC_CURVES = 16;
  
  private static final int ADDITIONAL_EC_PARAMETERS = 32;
  
  private static final int ALL = 63;
  
  private static final String THREAD_LOCAL_EC_IMPLICITLY_CA_STR = "threadlocalecimplicitlyca";
  
  private static final String EC_IMPLICITLY_CA_STR = "ecimplicitlyca";
  
  private static final String THREAD_LOCAL_DH_DEFAULT_PARAMS_STR = "threadlocaldhdefaultparams";
  
  private static final String DH_DEFAULT_PARAMS_STR = "dhdefaultparams";
  
  private static final String ACCEPTABLE_EC_CURVES_STR = "acceptableeccurves";
  
  private static final String ADDITIONAL_EC_PARAMETERS_STR = "additionalecparameters";
  
  private static final String ALL_STR = "all";
  
  private final String actions;
  
  private final int permissionMask;
  
  public ProviderConfigurationPermission(String paramString) {
    super(paramString);
    this.actions = "all";
    this.permissionMask = 63;
  }
  
  public ProviderConfigurationPermission(String paramString1, String paramString2) {
    super(paramString1, paramString2);
    this.actions = paramString2;
    this.permissionMask = calculateMask(paramString2);
  }
  
  private int calculateMask(String paramString) {
    StringTokenizer stringTokenizer = new StringTokenizer(Strings.toLowerCase(paramString), " ,");
    int i = 0;
    while (stringTokenizer.hasMoreTokens()) {
      String str = stringTokenizer.nextToken();
      if (str.equals("threadlocalecimplicitlyca")) {
        i |= 0x1;
        continue;
      } 
      if (str.equals("ecimplicitlyca")) {
        i |= 0x2;
        continue;
      } 
      if (str.equals("threadlocaldhdefaultparams")) {
        i |= 0x4;
        continue;
      } 
      if (str.equals("dhdefaultparams")) {
        i |= 0x8;
        continue;
      } 
      if (str.equals("acceptableeccurves")) {
        i |= 0x10;
        continue;
      } 
      if (str.equals("additionalecparameters")) {
        i |= 0x20;
        continue;
      } 
      if (str.equals("all"))
        i |= 0x3F; 
    } 
    if (i == 0)
      throw new IllegalArgumentException("unknown permissions passed to mask"); 
    return i;
  }
  
  public String getActions() {
    return this.actions;
  }
  
  public boolean implies(Permission paramPermission) {
    if (!(paramPermission instanceof org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission))
      return false; 
    if (!getName().equals(paramPermission.getName()))
      return false; 
    org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission providerConfigurationPermission = (org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission)paramPermission;
    return ((this.permissionMask & providerConfigurationPermission.permissionMask) == providerConfigurationPermission.permissionMask);
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission) {
      org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission providerConfigurationPermission = (org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission)paramObject;
      return (this.permissionMask == providerConfigurationPermission.permissionMask && getName().equals(providerConfigurationPermission.getName()));
    } 
    return false;
  }
  
  public int hashCode() {
    return getName().hashCode() + this.permissionMask;
  }
}
