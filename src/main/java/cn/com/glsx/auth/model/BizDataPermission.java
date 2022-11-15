package cn.com.glsx.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BizDataPermission {

    private Long roleId;

    /**
     * 业务数据权限（1结清数据）
     */
    private Integer type;

    /**
     * 业务数据权限可见度（1可见，2不可见）
     */
    private Integer visibility;

}
