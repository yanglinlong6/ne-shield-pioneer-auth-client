package cn.com.glsx.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * @author: taoyr
 **/
@Data
public class Menu implements Serializable {

    private Long menuId;

    /**
     * 菜单名
     */
    private String menuName;

    /**
     * 前端路由
     */
    private String frontRoute;

    /**
     * 后端路由
     */
    private String afterRoute;

    private String permissionTag;

    /**
     * 类型 1目录，2菜单，3按钮
     */
    private Integer type;

    /**
     * 父菜单id
     */
    private Long parentId;

    /**
     * 排序
     */
    private Integer orderNum;

    /**
     * 状态 0=不显示 1=显示
     */
    private Integer enableStatus;

}
