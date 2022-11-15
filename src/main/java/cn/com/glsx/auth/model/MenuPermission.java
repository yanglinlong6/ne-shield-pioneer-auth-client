package cn.com.glsx.auth.model;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author: taoyr
 **/
@Data
@Accessors(chain = true)
public class MenuPermission {

    private String permissionTag;

    private String interfaceUrl;

}
