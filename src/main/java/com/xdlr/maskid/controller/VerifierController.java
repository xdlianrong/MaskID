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
import com.xdlr.maskid.demo.common.model.VerifyCredentialModel;
import com.xdlr.maskid.service.MaskIdService;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.util.DataToolUtils;

/**
 * Verifier Controller.
 *
 * @author xdlr
 */
@RestController
@Api(description = "Verifier: Credential的使用者。"
        + "会验证实体对maskid的所有权，其次在链上验证Credential的真实性，以便处理相关业务。",
        tags = {"Verifier相关接口"}, position = 0)
public class VerifierController {

    private static final Logger logger = LoggerFactory.getLogger(VerifierController.class);

    @Autowired
    private MaskIdService maskIdService;

    /**
     * verifyEvidence Credential.
     *
     * @param verifyCredentialModel credential in JSON format
     * @return true is success, false is failure
     */
    @ApiOperation(value = "验证凭证是否正确")
    @PostMapping("/step1/verifyCredential")
    public ResponseData<Boolean> verifyCredential(
            @ApiParam(name = "verifyCredentialModel", value = "验证电子凭证模板")
            @RequestBody VerifyCredentialModel verifyCredentialModel) {

        logger.info("verifyCredentialModel:{}", verifyCredentialModel);

        if (null == verifyCredentialModel) {
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        // call method to verifyEvidence credential.
        try {
            return maskIdService.verifyCredential(
                    DataToolUtils.mapToCompactJson(verifyCredentialModel.getCredential()));
        } catch (Exception e) {
            logger.error("verifyCredential error", e);
            return new ResponseData<>(null, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        }
    }
}
