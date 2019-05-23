package com.jt.sys.controller;

import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.jt.common.util.ShiroUtils;
import com.jt.common.vo.JsonResult;
import com.jt.common.vo.PageObject;
import com.jt.sys.entity.SysUser;
import com.jt.sys.service.SysUserService;
import com.jt.sys.vo.SysUserDeptResult;

@RequestMapping("/user/")
@Controller
public class SysUserController {
	@Autowired
	private SysUserService sysUserService;

	/**
	 * 用户页面
	 * 
	 * @return
	 */
	@RequestMapping("doUserListUI")
	public String doUserListUI() {
		return "sys/user_list";
	}

	/**
	 * 添加用户页面
	 * 
	 * @return
	 */
	@RequestMapping("doUserEditUI")
	public String doUserEditUI() {
		return "sys/user_edit";
	}

	@RequestMapping("doFindObjectById")
	@ResponseBody
	public JsonResult doFindObjectById(Integer id) {
		Map<String, Object> map = sysUserService.findObjectById(id);
		return new JsonResult(map);
	}
	/**
	 * 	保存添加用户,及用户权限
	 * @param entity
	 * @param roleIds
	 * @return
	 */
	@RequestMapping("doUpdateObject")
	@ResponseBody
	public JsonResult doUpdateObject(SysUser entity, Integer[] roleIds) {
		sysUserService.updateObject(entity, roleIds);
		return new JsonResult("update ok");
	}

	@RequestMapping("doSaveObject")
	@ResponseBody
	public JsonResult doSaveObject(SysUser entity, Integer[] roleIds) {
		SysUser user = ShiroUtils.getPrincipal();
		entity.setCreatedUser(user.getUsername());
		entity.setModifiedUser(user.getUsername());
		sysUserService.saveObject(entity, roleIds);
		return new JsonResult("save ok");
	}

	@RequestMapping("doValidById")
	@ResponseBody
	public JsonResult doValidById(Integer id, Integer valid) {
		System.out.println(sysUserService.getClass().getName());
		SysUser user = (SysUser) SecurityUtils.getSubject().getPrincipal();
		sysUserService.validById(id, valid, user.getUsername());
		return new JsonResult("update ok");
	}
	/**
	 * 	页面显示所有用户
	 * @param username
	 * @param pageCurrent
	 * @return
	 */
	@RequestMapping("doFindPageObjects")
	@ResponseBody
	public JsonResult doFindPageObjects(String username, Integer pageCurrent) {
		PageObject<SysUserDeptResult> pageObject = sysUserService.findPageObjects(username, pageCurrent);
		return new JsonResult(pageObject);
	}
}
