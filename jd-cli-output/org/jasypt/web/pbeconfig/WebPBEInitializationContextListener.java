package org.jasypt.web.pbeconfig;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

public final class WebPBEInitializationContextListener implements ServletContextListener {
  public static final String INIT_PARAM_INITIALIZER_CLASS_NAME = "webPBEInitializerClassName";
  
  public void contextDestroyed(ServletContextEvent sce) {}
  
  public void contextInitialized(ServletContextEvent sce) {
    String className = sce.getServletContext().getInitParameter("webPBEInitializerClassName");
    if (CommonUtils.isEmpty(className))
      throw new EncryptionInitializationException("webPBEInitializerClassName context initialization parameter not set in web.xml"); 
    Class<?> initializerClass = null;
    try {
      initializerClass = Thread.currentThread().getContextClassLoader().loadClass(className);
    } catch (ClassNotFoundException e) {
      throw new EncryptionInitializationException(e);
    } 
    if (!WebPBEInitializer.class.isAssignableFrom(initializerClass))
      throw new EncryptionInitializationException("Class " + className + " does not implement interface " + WebPBEInitializer.class
          
          .getName()); 
    WebPBEInitializer initializer = null;
    try {
      initializer = (WebPBEInitializer)initializerClass.newInstance();
    } catch (InstantiationException e) {
      throw new EncryptionInitializationException(e);
    } catch (IllegalAccessException e) {
      throw new EncryptionInitializationException(e);
    } 
    initializer.initializeWebPBEConfigs();
  }
}
