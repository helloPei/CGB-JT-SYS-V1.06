package com.jt.common.aspect;

import java.util.logging.Logger;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

/**
 * 定义一个监控切面,监控方法开始执行和结束执行的时间.
 * @author 速度
 * 通知结构关系如下：
 * try{
 *   @Before
 *   target.method();//目标对象方法执行
 *   @AfterReturning
 * }catch(Exception e){
 *   @AfterThrowing
 *   throw e;
 * }finally{
 *   @After
 * }
 * 
 */
@Order(2)
@Aspect
@Service
public class MonitorAspect {//横切面
	//构建日志对象
	private Logger log=
	Logger.getLogger(MonitorAspect.class.getName());
	/**
	 * 定义切入点:PointCut(在哪些点切入扩展功能)
	 * 在当前应用中指的是对哪些方法的执行
	 * 进行业务监控
	 * 其中bean为AOP中的一个切入点表达式
	 */
	//@Pointcut("bean(sysConfigServiceImpl)")
    @Pointcut("bean(*ServiceImpl)")
	public void monitorPointCut(){}
    /**
     * Before通知(切点方法执行之前执行)
     */
    @Before("monitorPointCut()")
    public void beforeMethod(JoinPoint joinPoint){//连接点
      log.info(doGetClassMethodInfo(joinPoint)+" before method");
    }
    /**
     * @AfterReturning 通知(方法正常结束时执行，after以后执行)
     * @param joinPoint
     */
    @AfterReturning("monitorPointCut()")
    public void afterReturningMethod(JoinPoint joinPoint){
      log.info(doGetClassMethodInfo(joinPoint)+"  returning");
    }
    /**
     * @AfterThrowing 通知(方法出现异常时执行,after之后执行)
     * @param joinPoint
     */
    @AfterThrowing("monitorPointCut()")
    public void afterThrowingMethod(JoinPoint joinPoint){
    	log.info(doGetClassMethodInfo(joinPoint)+" throwing exception");
    }
    /**
     * After 通知(切入点方法执行之后执行)
     */
    @After("monitorPointCut()")
    public void afterMethod(JoinPoint joinPoint){
        log.info(doGetClassMethodInfo(joinPoint)+" after method");
    }
    
    private String doGetClassMethodInfo(JoinPoint joinPoint){
    	MethodSignature signature =(MethodSignature)joinPoint.getSignature();
        Class<?> c=joinPoint.getTarget().getClass();
        String methodName=signature.getName();
    	return c.getName()+"."+methodName;
    }
}
