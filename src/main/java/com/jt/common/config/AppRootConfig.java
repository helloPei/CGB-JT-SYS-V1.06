package com.jt.common.config;

import java.io.IOException;
import java.util.LinkedHashMap;

import javax.sql.DataSource;

import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.alibaba.druid.pool.DruidDataSource;

@Configuration
@PropertySource(value="classpath:configs.properties")
@ComponentScan(value="com.jt",
excludeFilters={@Filter(type=FilterType.ANNOTATION,classes={Controller.class})})
@MapperScan(basePackages="com.jt.**.dao")
@EnableAspectJAutoProxy //启用AOP(<aop:aspectj-autoproxy/>)
@EnableTransactionManagement
public class AppRootConfig {//service,dao
	 /**
	  * 让系统支持多个properties文件应用
	  * @return
	  */
	 @Bean
	 public PropertySourcesPlaceholderConfigurer newPropertyPlaceholderConfigurer(){
		 return new PropertySourcesPlaceholderConfigurer();
	 }
     /**配置数据源对象:druid*/
	 @Bean(value="dataSource",initMethod="init",destroyMethod="close")
	 public DataSource newDruidDataSource(
			@Value("${jdbcDriver}")String driverClass,
			@Value("${jdbcUrl}")String jdbcUrl,
			@Value("${jdbcUser}")String username,
			@Value("${jdbcPassword}")String password){
		 DruidDataSource ds=new DruidDataSource();
		 ds.setDriverClassName(driverClass);
		 ds.setUrl(jdbcUrl);
		 ds.setUsername(username);
		 ds.setPassword(password);
		 //ds.setMaxActive(maxActive);
		 //ds.setMaxWait(maxWaitMillis);
		 //ds.setLoginTimeout(1);
		 return ds;
	 }
	 @Bean("sqlSessionFactory")
	 public SqlSessionFactoryBean newSqlSessionFactoryBean(
			 @Autowired DataSource dataSource) throws IOException{
		 SqlSessionFactoryBean fBean=new SqlSessionFactoryBean();
		 fBean.setDataSource(dataSource);
		 Resource[] mapperLocations=
		 new PathMatchingResourcePatternResolver()
		 .getResources("classpath:mapper/sys/*.xml");
		 fBean.setMapperLocations(mapperLocations);
		 return fBean;
	 }
	 //=======shiro=============
	 
	 @Bean
	 public EhCacheManager newCacheManager() {
		 EhCacheManager cManager=new EhCacheManager();
		 cManager.setCacheManagerConfigFile("classpath:ehcache.xml");
		 return cManager;
	 }
	 @Bean("securityManager ")
	 public DefaultWebSecurityManager 
	      newDefaultWebSecurityManager(
	    		  AuthorizingRealm realm,EhCacheManager cacheManager){
		 DefaultWebSecurityManager sManager=
		 new DefaultWebSecurityManager();
		 sManager.setRealm(realm);
		 sManager.setCacheManager(cacheManager);
		 return sManager;
	 }
	 /**
	  * 配置Shiro的過濾器Bean工廠
	  * @param securityManager
	  * @return
	  */
	 @Bean("shiroFilterFactoryBean")
	 public ShiroFilterFactoryBean newShiroFilterFactoryBean(
	 			SecurityManager securityManager){//shiro 包
	 		ShiroFilterFactoryBean bean=
	 		new ShiroFilterFactoryBean();
	 		bean.setSecurityManager(securityManager);
	 	    //当此用户是一个非认证用户,需要先登陆进行认证
	 		bean.setLoginUrl("/doLoginUI.do");
	 		//定義請求過濾規則
	 		LinkedHashMap<String,String> fcMap=
	 		new LinkedHashMap<>();
	 		fcMap.put("/bower_components/**","anon");//anon表示允许匿名访问
	 		fcMap.put("/build/**", "anon");
	 		fcMap.put("/dist/**","anon");
	 		fcMap.put("/plugins/**","anon");
	 		fcMap.put("/doLogin.do","anon");
	 		fcMap.put("/doLogout.do ","logout");
	 		fcMap.put("/**", "authc");//必须授权才能访问
	 		bean.setFilterChainDefinitionMap(fcMap);
	 		return bean;
	 }
	 /***
	  * 配置shiro框架组件的生命周期管理对象
	  * @return
	  */
	 @Bean("lifecycleBeanPostProcessor")
	 public LifecycleBeanPostProcessor 
	        newLifecycleBeanPostProcessor(){
	 	return new LifecycleBeanPostProcessor();
	 }

     /**配置负责为Bean对象(需要授权访问的方法所在的对象)
      * 创建代理对象的Bean组件*/
	 @DependsOn(value="lifecycleBeanPostProcessor")
	 @Bean
	 public DefaultAdvisorAutoProxyCreator newDefaultAdvisorAutoProxyCreator(){
	   return new DefaultAdvisorAutoProxyCreator();
	 }
     /**
      * 配置授权属性应用对象(在执行授权操作时需要用到此对象)
      * @param securityManager
      * @return
      */
	 @Bean
	 public AuthorizationAttributeSourceAdvisor 
	        newAuthorizationAttributeSourceAdvisor(
	 		SecurityManager securityManager){
	 		AuthorizationAttributeSourceAdvisor bean=
	 	    new AuthorizationAttributeSourceAdvisor();
	 		bean.setSecurityManager(securityManager);
	 		return bean;
	 }
	 //======transaction manager===========
	 
	 @Bean("txManager")
	 public DataSourceTransactionManager 
	        newDataSourceTransactionManager(
			 @Autowired DataSource dataSource){
		 DataSourceTransactionManager tManager=
			new DataSourceTransactionManager();
		 tManager.setDataSource(dataSource);
		 return tManager;
	 }

}









