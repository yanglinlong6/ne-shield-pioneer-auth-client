package cn.com.glsx.auth.model;

import lombok.Data;

@Data
public class Department {

    private Long deptId;
    private String departmentName;
    private Long tenantId;

}
