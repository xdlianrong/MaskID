package com.xdlr.maskid.service.impl;

import java.util.HashMap;
import java.util.Map;

import com.xdlr.wedpr.selectivedisclosure.CredentialTemplateEntity;
import org.apache.commons.lang3.StringUtils;
import org.bcos.web3j.crypto.Sign.SignatureData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xdlr.maskid.constant.CredentialConstant;
import com.xdlr.maskid.constant.ErrorCode;
import com.xdlr.maskid.constant.JsonSchemaConstant;
import com.xdlr.maskid.constant.maskidConstant;
import com.xdlr.maskid.protocol.base.Cpt;
import com.xdlr.maskid.protocol.base.CptBaseInfo;
import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.base.maskidPrivateKey;
import com.xdlr.maskid.protocol.request.CptMapArgs;
import com.xdlr.maskid.protocol.request.CptStringArgs;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.protocol.response.RsvSignature;
import com.xdlr.maskid.rpc.CptService;
import com.xdlr.maskid.suite.cache.CacheManager;
import com.xdlr.maskid.suite.cache.CacheNode;
import com.xdlr.maskid.util.DataToolUtils;
import com.xdlr.maskid.util.maskidUtils;

/**
 * Service implementation for operation on CPT (Claim Protocol Type).
 *
 * @author lingfenghe
 */
public class CptServiceImpl extends AbstractService implements CptService {

    private static final Logger logger = LoggerFactory.getLogger(CptServiceImpl.class);
    //获取CPT缓存节点
    private static CacheNode<ResponseData<Cpt>> cptCahceNode =
            CacheManager.registerCacheNode("SYS_CPT", 1000 * 3600 * 24L);

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error(
                    "[registerCpt1] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setmaskidAuthentication(args.getmaskidAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                    DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    /**
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptStringArgs args) {

        try {
            if (args == null) {
                logger.error(
                        "[registerCpt1]input CptStringArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setmaskidAuthentication(args.getmaskidAuthentication());
            Map<String, Object> cptJsonSchemaMap =
                    DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class);
            cptMapArgs.setCptJsonSchema(cptJsonSchemaMap);
            return this.registerCpt(cptMapArgs);
        } catch (Exception e) {
            logger.error("[registerCpt1] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args, Integer cptId) {
        if (args == null || cptId == null || cptId <= 0) {
            logger.error("[registerCpt] input argument is illegal");
            return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
        }
        try {
            ErrorCode errorCode =
                    this.validateCptArgs(
                            args.getmaskidAuthentication(),
                            args.getCptJsonSchema()
                    );
            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String maskid = args.getmaskidAuthentication().getmaskid();
            maskidPrivateKey maskidPrivateKey = args.getmaskidAuthentication().getmaskidPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                    maskid,
                    cptJsonSchemaNew,
                    maskidPrivateKey);
            String address = maskidUtils.convertmaskidToAddress(maskid);
            return cptServiceEngine.registerCpt(cptId, address, cptJsonSchemaNew, rsvSignature,
                    maskidPrivateKey.getPrivateKey());
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to register a new CPT to the blockchain.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> registerCpt(CptMapArgs args) {

        try {
            if (args == null) {
                logger.error("[registerCpt]input CptMapArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            ErrorCode validateResult =
                    this.validateCptArgs(
                            args.getmaskidAuthentication(),
                            args.getCptJsonSchema()
                    );

            if (validateResult.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, validateResult);
            }

            String maskid = args.getmaskidAuthentication().getmaskid();
            maskidPrivateKey maskidPrivateKey = args.getmaskidAuthentication().getmaskidPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                    maskid,
                    cptJsonSchemaNew,
                    maskidPrivateKey);
            String address = maskidUtils.convertmaskidToAddress(maskid);
            return cptServiceEngine.registerCpt(address, cptJsonSchemaNew, rsvSignature,
                    maskidPrivateKey.getPrivateKey());
        } catch (Exception e) {
            logger.error("[registerCpt] register cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * this is used to query cpt with the latest version which has been registered.
     *
     * @param cptId the cpt id
     * @return the response data
     */
    public ResponseData<Cpt> queryCpt(Integer cptId) {

        try {
            if (cptId == null || cptId < 0) {
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            String cptIdStr = String.valueOf(cptId);
            ResponseData<Cpt> result = cptCahceNode.get(cptIdStr);
            if (result == null) {
                result = cptServiceEngine.queryCpt(cptId);
                if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                    cptCahceNode.put(cptIdStr, result);
                }
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] query cpt failed due to unknown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptStringArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt1]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            CptMapArgs cptMapArgs = new CptMapArgs();
            cptMapArgs.setmaskidAuthentication(args.getmaskidAuthentication());
            cptMapArgs.setCptJsonSchema(
                    DataToolUtils.deserialize(args.getCptJsonSchema(), HashMap.class));
            return this.updateCpt(cptMapArgs, cptId);
        } catch (Exception e) {
            logger.error("[updateCpt1] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * This is used to update a CPT data which has been register.
     *
     * @param args the args
     * @return the response data
     */
    public ResponseData<CptBaseInfo> updateCpt(CptMapArgs args, Integer cptId) {

        try {
            if (args == null) {
                logger.error("[updateCpt]input UpdateCptArgs is null");
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            if (cptId == null || cptId.intValue() < 0) {
                logger.error("[updateCpt]input cptId illegal");
                return new ResponseData<>(null, ErrorCode.CPT_ID_ILLEGAL);
            }
            ErrorCode errorCode =
                    this.validateCptArgs(
                            args.getmaskidAuthentication(),
                            args.getCptJsonSchema()
                    );

            if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
                return new ResponseData<>(null, errorCode);
            }

            String maskid = args.getmaskidAuthentication().getmaskid();
            maskidPrivateKey maskidPrivateKey = args.getmaskidAuthentication().getmaskidPrivateKey();
            String cptJsonSchemaNew = this.cptSchemaToString(args);
            RsvSignature rsvSignature = sign(
                    maskid,
                    cptJsonSchemaNew,
                    maskidPrivateKey);
            String address = maskidUtils.convertmaskidToAddress(maskid);
            ResponseData<CptBaseInfo> result = cptServiceEngine.updateCpt(
                    cptId,
                    address,
                    cptJsonSchemaNew,
                    rsvSignature,
                    maskidPrivateKey.getPrivateKey());
            if (result.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
                cptCahceNode.remove(String.valueOf(cptId));
            }
            return result;
        } catch (Exception e) {
            logger.error("[updateCpt] update cpt failed due to unkown error. ", e);
            return new ResponseData<>(null, ErrorCode.UNKNOW_ERROR);
        }
    }


    private RsvSignature sign(
            String cptPublisher,
            String jsonSchema,
            maskidPrivateKey cptPublisherPrivateKey) {

        StringBuilder sb = new StringBuilder();
        sb.append(cptPublisher);
        sb.append(maskidConstant.PIPELINE);
        sb.append(jsonSchema);
        SignatureData signatureData =
                DataToolUtils.signMessage(sb.toString(), cptPublisherPrivateKey.getPrivateKey());
        return DataToolUtils.convertSignatureDataToRsv(signatureData);
    }

    private ErrorCode validateCptArgs(
            maskidAuthentication maskidAuthentication,
            Map<String, Object> cptJsonSchemaMap) throws Exception {

        if (maskidAuthentication == null) {
            logger.error("Input cpt maskidAuthentication is invalid.");
            return ErrorCode.maskid_AUTHORITY_INVALID;
        }

        String maskid = maskidAuthentication.getmaskid();
        if (!maskidUtils.ismaskidValid(maskid)) {
            logger.error("Input cpt publisher : {} is invalid.", maskid);
            return ErrorCode.maskid_INVALID;
        }

        ErrorCode errorCode = validateCptJsonSchemaMap(cptJsonSchemaMap);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return errorCode;
        }
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        maskidPrivateKey maskidPrivateKey = maskidAuthentication.getmaskidPrivateKey();
        if (maskidPrivateKey == null
                || StringUtils.isEmpty(maskidPrivateKey.getPrivateKey())) {
            logger.error(
                    "Input cpt publisher private key : {} is in valid.",
                    maskidPrivateKey
            );
            return ErrorCode.maskid_PRIVATEKEY_INVALID;
        }

        if (!maskidUtils.validatePrivateKeymaskidMatches(maskidPrivateKey, maskid)) {
            return ErrorCode.maskid_PRIVATEKEY_DOES_NOT_MATCH;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode validateCptJsonSchemaMap(
            Map<String, Object> cptJsonSchemaMap) throws Exception {
        if (cptJsonSchemaMap == null || cptJsonSchemaMap.isEmpty()) {
            logger.error("Input cpt json schema is invalid.");
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        //String cptJsonSchema = JsonUtil.objToJsonStr(cptJsonSchemaMap);
        String cptJsonSchema = DataToolUtils.serialize(cptJsonSchemaMap);
        if (!DataToolUtils.isCptJsonSchemaValid(cptJsonSchema)) {
            logger.error("Input cpt json schema : {} is invalid.", cptJsonSchemaMap);
            return ErrorCode.CPT_JSON_SCHEMA_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    /**
     * create new cpt json schema.
     *
     * @param cptJsonSchema Map
     * @return String
     */
    private String cptSchemaToString(CptMapArgs args) throws Exception {

        Map<String, Object> cptJsonSchema = args.getCptJsonSchema();
        Map<String, Object> cptJsonSchemaNew = new HashMap<String, Object>();
        cptJsonSchemaNew.put(JsonSchemaConstant.SCHEMA_KEY, JsonSchemaConstant.SCHEMA_VALUE);
        cptJsonSchemaNew.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATA_TYPE_OBJECT);
        cptJsonSchemaNew.putAll(cptJsonSchema);
        String cptType = args.getCptType().getName();
        cptJsonSchemaNew.put(CredentialConstant.CPT_TYPE_KEY, cptType);
        return DataToolUtils.serialize(cptJsonSchemaNew);
    }

    /* (non-Javadoc)
     * @see com.xdlr.maskid.rpc.CptService#queryCredentialTemplate(java.lang.Integer)
     */
    @Override
    public ResponseData<CredentialTemplateEntity> queryCredentialTemplate(Integer cptId) {

        return cptServiceEngine.queryCredentialTemplate(cptId);
    }
}
