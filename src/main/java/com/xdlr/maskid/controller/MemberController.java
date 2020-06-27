package com.xdlr.maskid.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.xdlr.maskid.constant.ErrorCode;
import com.xdlr.maskid.demo.common.model.AuthorityIssuerModel;
import com.xdlr.maskid.demo.service.DemoService;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;

/**
 * Member Controller.
 *
 * @author xdlr
 */
@RestController
@Api(description = "Committee Member: "
        + "委员会机构成员，管理Authority Issuer的委员会机构的成员",
        tags = {"CommitteeMember相关接口"})
public class DemoMemberController {

    private static final Logger logger = LoggerFactory.getLogger(MemberController.class);

    @Autowired
    private MaskIdService maskIdService;


    /**
     * create maskid without parameters and call the settings property method.
     *
     * @return returns maskid and public key
     */
    @ApiOperation(value = "创建maskid")
    @PostMapping("/step1/member/createmaskid")
    public ResponseData<CreatemaskidDataResult> createMaskId() {
        return maskIdService.createMaskId();
    }


    /**
     * registered on the chain of institutions as authoritative bodies.
     *
     * @return true is success, false is failure.
     */
    @ApiOperation(value = "注册成为权威机构")
    @PostMapping("/step2/registerAuthorityIssuer")
    public ResponseData<Boolean> registerAuthorityIssuer(
            @ApiParam(name = "authorityIssuerModel", value = "注册权威机构模板")
            @RequestBody AuthorityIssuerModel authorityIssuerModel) {

        if (null == authorityIssuerModel) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        String issuer = authorityIssuerModel.getIssuer();
        String authorityName = authorityIssuerModel.getOrgId();

        logger.info("param,issuer:{},orgId:{}", issuer, authorityName);

        // call method registered as authority.
        return maskIdService.registerAuthorityIssuer(issuer, authorityName);
    }

}
