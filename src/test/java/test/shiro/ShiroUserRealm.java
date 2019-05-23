package test.shiro;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.alibaba.druid.util.StringUtils;
import com.jt.sys.dao.SysMenuDao;
import com.jt.sys.dao.SysRoleMenuDao;
import com.jt.sys.dao.SysUserDao;
import com.jt.sys.dao.SysUserRoleDao;
import com.jt.sys.entity.SysUser;

//AuthorizingRealm(提供了认证数据)
@Service
public class ShiroUserRealm extends AuthorizingRealm{
	@Autowired
	private SysUserRoleDao sysUserRoleDao;
	@Autowired
	private SysRoleMenuDao sysRoleMenuDao;
	@Autowired
	private SysMenuDao sysMenuDao;
	@Autowired
	private SysUserDao sysUserDao;
	/* ConcurrentHashMap 红黑树map(线程安全，处理高并发)
	 * Hashtable 是锁整个表，性能差 */
	//自定义缓存map(缓存用户权限信息)
	private Map<String,SimpleAuthorizationInfo> authorMap = new ConcurrentHashMap<>();
	/** 设置凭证(密码)加密匹配器 */
	@Override
	public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
		HashedCredentialsMatcher cMatcher = new HashedCredentialsMatcher();
		cMatcher.setHashAlgorithmName("MD5");//MD5加密次数
		super.setCredentialsMatcher(cMatcher);
	}

	/** 此方法提供认证数据的获取操作 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		//获取token信息
		String username = (String) token.getPrincipal();
		//根据用户名获取用户对象
		SysUser user = sysUserDao.findUserByUserName(username);
		//判断用户是否存在
		if(user == null)throw new UnknownAccountException();//用户不存在
		//判断用户是否被禁用
		if(user.getValid() == 0)throw new LockedAccountException();//用户已禁用
		//封装凭证盐值、一个字节数组以及一些编码操作
		ByteSource credentialsSalt = ByteSource.Util.bytes(user.getSalt());
		//封装凭证信息
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user, //principal查询获取的用户对象
				user.getPassword(), //hashedCredentials,已加密的凭证
				credentialsSalt, //凭证盐值
				getName());//realmName
		//将凭证信息提交给认证管理器
		return info;
	}
	
	/** 此方法提供授权数据的获取操作，当我们访问系统中的一个需要授权访问的方法，shiro框架底层会通知如下方法获取用户权限信息 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		//获取登录用户身份对象
		SysUser user = (SysUser) principals.getPrimaryPrincipal();
		//判断map缓存是否有用户权限信息get
		if(authorMap.containsKey(user.getUsername()))return authorMap.get(user.getUsername());
		//根据用户id获取用户拥有角色权限
		List<Integer> roleIds = sysUserRoleDao.findRoleIdsByUserId(user.getId());
		if(roleIds==null||roleIds.size()==0)throw new AuthorizationException("无权访问");
		//根据角色id获取角色对应的访问菜单
		List<Integer> menuIds = sysRoleMenuDao.findMenuIdsByRoleId(roleIds.toArray(new Integer[]{}));
		if(menuIds==null||menuIds.size()==0)throw new AuthorizationException("无权访问");
		//根据菜单id获取菜单表定义的权限标识
		List<String> permissions = sysMenuDao.findPermissions(menuIds.toArray(new Integer[]{}));
		Set<String> permissionSet = new HashSet<>();
		for(String per:permissions) {//遍历去重、去空(null,"")
			if(!StringUtils.isEmpty(per)) {
				permissionSet.add(per);
			}
		}
		//创建自定义缓存map(用户权限对象)
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setStringPermissions(permissionSet);
		//把用户权限信息储存到自定义缓存map
		authorMap.put(user.getUsername(),info);
		return info;
	}

}
