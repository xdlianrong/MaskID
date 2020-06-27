package com.xdlr.maskid.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.xdlr.maskid.service.MaskIdService;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;

/**
 * UserAgent Controller.
 *
 * @author xdlr
 */
@RestController
@Api(description = "User Agent / Credential Repository: "
        + "用户（实体）在此生成maskid。为了便于使用，实体也可将自己的私钥、持有的Credential托管于此。",
        tags = {"UserAgent相关接口"})
public class UserAgentController {

    @Autowired
    private MaskIdService maskIdService;

    /**
     * create maskid without parameters and call the settings property method.
     *
     * @return returns maskid and public key
     */
    @ApiOperation(value = "创建maskid")
    @PostMapping("/step1/userAgent/createmaskid")
    public ResponseData<CreatemaskidDataResult> createMaskId() {
        return maskIdService.createMaskId();
    }

}
