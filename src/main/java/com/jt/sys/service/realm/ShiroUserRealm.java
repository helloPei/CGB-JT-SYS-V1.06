package com.jt.sys.service.realm;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.jt.sys.dao.SysMenuDao;
import com.jt.sys.dao.SysRoleMenuDao;
import com.jt.sys.dao.SysUserDao;
import com.jt.sys.dao.SysUserRoleDao;
import com.jt.sys.entity.SysUser;

@Service
public class ShiroUserRealm extends AuthorizingRealm {
	private static Logger logger = Logger.getLogger(ShiroUserRealm.class);
    @Autowired
	private SysUserDao sysUserDao;
    @Autowired
    private SysUserRoleDao sysUserRoleDao;
    @Autowired
    private SysRoleMenuDao sysRoleMenuDao;
    @Autowired
    private SysMenuDao sysMenuDao;
    
    /**
     * 	设置凭证(Credentials)匹配器
     */
	@Override
	public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
		HashedCredentialsMatcher cMatcher = new HashedCredentialsMatcher();
		cMatcher.setHashAlgorithmName("MD5");
		//设置加密的次数(这个次数应该与保存密码时那个加密次数一致)
		//cMatcher.setHashIterations(5);
		super.setCredentialsMatcher(cMatcher);
	}
	/**
	 * 	负责完成认证领域信息的获取以及封装
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
			throws AuthenticationException {
		logger.info("==doGetAuthenticationInfo===");
		//1.从token对象获取用户名(用户输入的)
		UsernamePasswordToken upToken = (UsernamePasswordToken)token;
		String username = upToken.getUsername();
		//2.基于用户名查询用户信息并进行身份校验
		SysUser user = sysUserDao.findUserByUserName(username);
		if(user==null)
			throw new AuthenticationException("此用户不存在");
		if(user.getValid()==0)
			throw new AuthenticationException("此用户已被禁用");
		//3.对用户信息进行封装
		ByteSource credentialsSalt = ByteSource.Util.bytes(user.getSalt());
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(
				user,//principal 用户身份
				user.getPassword(),//hashedCredentials已加密的凭证
				credentialsSalt,//credentialsSalt 密码加密时使用的盐
				getName());//realmName 当前方法所在对象的名字
		return info;//返回给谁?认证管理器
	}
	/**
	 * 	负责完成用户权限领域信息的获取以及封装
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("==doGetAuthorizationInfo===");
		//1.基于用户id查找角色id
		SysUser user = (SysUser)principals.getPrimaryPrincipal();
		List<Integer> roleIds = sysUserRoleDao.findRoleIdsByUserId(user.getId());
		System.out.println("roleIds="+roleIds);
		//2.基于角色id查找菜单id
		Integer[] array={};
		List<Integer>  menuIds = sysRoleMenuDao.findMenuIdsByRoleId(roleIds.toArray(array));
		//3.基于菜单id查找权限标识
		List<String> permissions = sysMenuDao.findPermissions(menuIds.toArray(array));
		//4.对权限标识进行去重和空的操作
		Set<String> set = new HashSet<String>();
		for(String permission:permissions){
			if(!StringUtils.isEmpty(permission)){
				set.add(permission);
			}
		}
		//5.对权限标识信息进行封装
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setStringPermissions(set);
		return info;//返回给授权管理器对象
	}
}
