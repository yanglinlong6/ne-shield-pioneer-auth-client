package cn.com.glsx.auth.model;

import lombok.Data;

@Data
public class UserGroup {

    private Long tenantId;
    private Long groupId;
    private String userGroupName;

}
