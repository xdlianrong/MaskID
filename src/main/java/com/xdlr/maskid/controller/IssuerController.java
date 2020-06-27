package com.xdlr.maskid.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
import com.xdlr.maskid.demo.common.model.CptModel;
import com.xdlr.maskid.demo.common.model.CreateCredentialModel;
import com.xdlr.maskid.demo.common.util.PrivateKeyUtil;
import com.xdlr.maskid.service.MaskIdService;
import com.xdlr.maskid.protocol.base.CptBaseInfo;
import com.xdlr.maskid.protocol.base.CredentialWrapper;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.util.DataToolUtils;

/**
 * Issuer Controller.
 *
 * @author xdlr
 */
@RestController
@Api(description = "Issuer: Credential的发行者。"
        tags = {"Issuer相关接口"})
public class IssuerController {

    private static final Logger logger = LoggerFactory.getLogger(IssuerController.class);

    @Autowired
    private MaskIdService maskIdService;

    /**
     * create maskid without parameters and call the settings property method.
     *
     * @return returns maskid and public key
     */
    @ApiOperation(value = "创建maskid")
    @PostMapping("/step1/issuer/createmaskid")
    public ResponseData<CreateMaskIdDataResult> createMaskId() {
        return maskIdService.createMaskId();
    }

    /**
     * institutional publication of CPT.
     * claim is a JSON object
     * @return returns CptBaseInfo
     */
    @ApiOperation(value = "注册CPT")
    @PostMapping("/step2/registCpt")
    public ResponseData<CptBaseInfo> registCpt(
            @ApiParam(name = "cptModel", value = "CPT模板")
            @RequestBody CptModel cptModel) {

        ResponseData<CptBaseInfo> response;
        try {
            if (null == cptModel) {
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            String publisher = cptModel.getPublisher();
            String claim = DataToolUtils.mapToCompactJson(cptModel.getClaim());

            // get the private key from the file according to maskid.
            String privateKey
                    = PrivateKeyUtil.getPrivateKeyByMaskId(PrivateKeyUtil.KEY_DIR, publisher);
            logger.info("param,publisher:{},privateKey:{},claim:{}", publisher, privateKey, claim);

            // converting claim in JSON format to map.
            Map<String, Object> claimMap = new HashMap<String, Object>();
            claimMap =
                    (Map<String, Object>) DataToolUtils.deserialize(
                            claim,
                            claimMap.getClass()
                    );

            // call method to register CPT on the chain.
            response = maskIdService.registCpt(publisher, privateKey, claimMap);
            logger.info("registCpt response: {}", DataToolUtils.objToJsonStrWithNoPretty(response));
            return response;
        } catch (Exception e) {
            logger.error("registCpt error", e);
            return new ResponseData<>(null, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        }
    }

    /**
     * institutional publication of Credential.
     *
     * @return returns  credential
     * @throws IOException  it's possible to throw an exception
     */
    @ApiOperation(value = "创建电子凭证")
    @PostMapping("/step3/createCredential")
    public ResponseData<CredentialWrapper> createCredential(
            @ApiParam(name = "createCredentialModel", value = "创建电子凭证模板")
            @RequestBody CreateCredentialModel createCredentialModel) {

        ResponseData<CredentialWrapper> response;
        try {

            if (null == createCredentialModel) {
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            // getting cptId data.
            Integer cptId = createCredentialModel.getCptId();
            // getting issuer data.
            String issuer = createCredentialModel.getIssuer();
            // getting claimData data.
            String claimData = DataToolUtils.mapToCompactJson(createCredentialModel.getClaimData());

            // get the private key from the file according to maskid.
            String privateKey = PrivateKeyUtil.getPrivateKeyByMaskId(PrivateKeyUtil.KEY_DIR, issuer);
            logger.info(
                    "param,cptId:{},issuer:{},privateKey:{},claimData:{}",
                    cptId,
                    issuer,
                    privateKey,
                    claimData
            );

            // converting claimData in JSON format to map.
            Map<String, Object> claimDataMap = new HashMap<String, Object>();
            claimDataMap =
                    (Map<String, Object>) DataToolUtils.deserialize(
                            claimData,
                            claimDataMap.getClass()
                    );

            // call method to create credentials.
            response = maskIdService.createCredential(cptId, issuer, privateKey, claimDataMap);
            logger.info("createCredential response: {}",
                    DataToolUtils.objToJsonStrWithNoPretty(response));
            return response;
        } catch (Exception e) {
            logger.error("createCredential error", e);
            return new ResponseData<CredentialWrapper>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }


}
