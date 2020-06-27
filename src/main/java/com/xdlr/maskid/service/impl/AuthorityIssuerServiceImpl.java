package com.xdlr.maskid.service.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xdlr.maskid.constant.ErrorCode;
import com.xdlr.maskid.constant.maskidConstant;
import com.xdlr.maskid.protocol.base.AuthorityIssuer;
import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.request.RegisterAuthorityIssuerArgs;
import com.xdlr.maskid.protocol.request.RemoveAuthorityIssuerArgs;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.rpc.AuthorityIssuerService;
import com.xdlr.maskid.rpc.maskidService;
import com.xdlr.maskid.util.maskidUtils;

/**
 * Service implementations for operations on Authority Issuer.
 *
 * @author xdlr
 */
public class AuthorityIssuerServiceImpl extends AbstractService implements AuthorityIssuerService {

    private static final Logger logger = LoggerFactory
            .getLogger(AuthorityIssuerServiceImpl.class);

    private MaskIdService maskidService = new MaskIdServiceImpl();

    /**
     * Register a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(RegisterAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRegisterAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }
        try {
            return authEngine.addAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("register has error, Error Message:{}", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Remove a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRemoveAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }

        try {
            return authEngine.removeAuthorityIssuer(args);
        } catch (Exception e) {
            logger.error("remove authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check whether the given maskid is an authority issuer.
     *
     * @param maskid the maskid
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> isAuthorityIssuer(String maskid) {

        if (!maskidUtils.ismaskidValid(maskid)) {
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
        String addr = maskidUtils.convertmaskidToAddress(maskid);
        try {
            return authEngine.isAuthorityIssuer(addr);
        } catch (Exception e) {
            logger.error("check authority issuer id failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Query the authority issuer information given maskid.
     *
     * @param maskid the maskid
     * @return the AuthorityIssuer response data
     */
    @Override
    public ResponseData<AuthorityIssuer> queryAuthorityIssuerInfo(String maskid) {
        if (!maskidUtils.ismaskidValid(maskid)) {
            return new ResponseData<>(null, ErrorCode.maskid_INVALID);
        }
        try {
            return authEngine.getAuthorityIssuerInfoNonAccValue(maskid);
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Get all of the authority issuer.
     *
     * @param index start position
     * @param num number of returned authority issuer in this request
     * @return Execution result
     */
    @Override
    public ResponseData<List<AuthorityIssuer>> getAllAuthorityIssuerList(Integer index,
                                                                         Integer num) {
        ErrorCode errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            List<String> addrList = authEngine.getAuthorityIssuerAddressList(index, num);
            List<AuthorityIssuer> authorityIssuerList = new ArrayList<>();
            for (String address : addrList) {
                String maskid = maskidUtils.convertAddressTomaskid(address);
                ResponseData<AuthorityIssuer> innerResponseData
                        = this.queryAuthorityIssuerInfo(maskid);
                if (innerResponseData.getResult() != null) {
                    authorityIssuerList.add(innerResponseData.getResult());
                }
            }
            return new ResponseData<>(authorityIssuerList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("query authority issuer list failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Register a new issuer type.
     *
     * @param callerAuth the caller
     * @param issuerType the specified issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> registerIssuerType(
            maskidAuthentication callerAuth,
            String issuerType
    ) {
        ErrorCode innerCode = isIssuerTypeValid(issuerType);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        innerCode = isCallerAuthValid(callerAuth);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            return authEngine
                    .registerIssuerType(issuerType, callerAuth.getmaskidPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("register issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }


    /**
     * Marked an issuer as the specified issuer type.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuermaskid the maskid of the issuer who will be marked as a specific issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> addIssuerIntoIssuerType(
            maskidAuthentication callerAuth,
            String issuerType,
            String targetIssuermaskid
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
                targetIssuermaskid);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = maskidUtils.convertmaskidToAddress(targetIssuermaskid);
            return authEngine.addIssuer(issuerType, issuerAddress,
                    callerAuth.getmaskidPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("add issuer into type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Removed an issuer from the specified issuer list.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuermaskid the maskid of the issuer to be removed from a specific issuer list
     * @return Execution result
     */
    public ResponseData<Boolean> removeIssuerFromIssuerType(
            maskidAuthentication callerAuth,
            String issuerType,
            String targetIssuermaskid
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
                targetIssuermaskid);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            String issuerAddress = maskidUtils.convertmaskidToAddress(targetIssuermaskid);
            return authEngine.removeIssuer(
                    issuerType,
                    issuerAddress,
                    callerAuth.getmaskidPrivateKey().getPrivateKey());
        } catch (Exception e) {
            logger.error("remove issuer from type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check if the given maskid is belonging to a specific issuer type.
     *
     * @param issuerType the issuer type
     * @param targetIssuermaskid the maskid
     * @return true if yes, false otherwise
     */
    public ResponseData<Boolean> isSpecificTypeIssuer(
            String issuerType,
            String targetIssuermaskid
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(false, errorCode);
        }
        if (!maskidService.ismaskidExist(targetIssuermaskid).getResult()) {
            return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
        }
        try {
            String address = maskidUtils.convertmaskidToAddress(targetIssuermaskid);
            return authEngine.isSpecificTypeIssuer(issuerType, address);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Get all specific typed issuer in a list.
     *
     * @param issuerType the issuer type
     * @param index the start position index
     * @param num the number of issuers
     * @return the list
     */
    public ResponseData<List<String>> getAllSpecificTypeIssuerList(
            String issuerType,
            Integer index,
            Integer num
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            return authEngine.getSpecificTypeIssuerList(issuerType, index, num);
        } catch (Exception e) {
            logger.error("get all specific issuers failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode isStartEndPosValid(Integer index, Integer num) {
        if (index == null || index < 0 || num == null || num <= 0
                || num > maskidConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isSpecificTypeIssuerArgsValid(
            maskidAuthentication callerAuth,
            String issuerType,
            String targetIssuermaskid
    ) {
        if (!maskidUtils.ismaskidValid(targetIssuermaskid)) {
            return ErrorCode.maskid_INVALID;
        }
        if (!maskidService.ismaskidExist(targetIssuermaskid).getResult()) {
            return ErrorCode.maskid_DOES_NOT_EXIST;
        }
        ErrorCode errorCode = isCallerAuthValid(callerAuth);
        if (errorCode.getCode() == ErrorCode.SUCCESS.getCode()) {
            return isIssuerTypeValid(issuerType);
        }
        return errorCode;
    }

    private ErrorCode isCallerAuthValid(maskidAuthentication callerAuth) {
        if (callerAuth == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!maskidUtils.ismaskidValid(callerAuth.getmaskid())) {
            return ErrorCode.maskid_INVALID;
        }
        if (!maskidService.ismaskidExist(callerAuth.getmaskid()).getResult()) {
            return ErrorCode.maskid_DOES_NOT_EXIST;
        }
        if (callerAuth.getmaskidPrivateKey() == null
                || StringUtils.isEmpty(callerAuth.getmaskidPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isIssuerTypeValid(String issuerType) {
        if (StringUtils.isEmpty(issuerType)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (issuerType.length() > maskidConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH) {
            return ErrorCode.SPECIFIC_ISSUER_TYPE_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRegisterAuthorityIssuerArgs(
            RegisterAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        ErrorCode errorCode = checkAuthorityIssuerArgsValidity(
                args.getAuthorityIssuer()
        );

        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            logger.error("register authority issuer format error!");
            return errorCode;
        }
        if (args.getmaskidPrivateKey() == null
                || StringUtils.isEmpty(args.getmaskidPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        // Need an extra check for the existence of maskid on chain, in Register Case.
        ResponseData<Boolean> innerResponseData = maskidService
                .ismaskidExist(args.getAuthorityIssuer().getmaskid());
        if (!innerResponseData.getResult()) {
            return ErrorCode.maskid_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRemoveAuthorityIssuerArgs(RemoveAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!maskidUtils.ismaskidValid(args.getmaskid())) {
            return ErrorCode.maskid_INVALID;
        }
        if (args.getmaskidPrivateKey() == null
                || StringUtils.isEmpty(args.getmaskidPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkAuthorityIssuerArgsValidity(AuthorityIssuer args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!maskidUtils.ismaskidValid(args.getmaskid())) {
            return ErrorCode.maskid_INVALID;
        }
        String name = args.getName();
        if (!isValidAuthorityIssuerName(name)) {
            return ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL;
        }
        String accValue = args.getAccValue();
        try {
            BigInteger accValueBigInteger = new BigInteger(accValue);
            logger.info(args.getmaskid() + " accValue is: " + accValueBigInteger.longValue());
            if (accValueBigInteger.compareTo(BigInteger.ZERO) < 0) {
                return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
            }
        } catch (Exception e) {
            logger.error("accValue is invalid.", e);
            return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
        }

        return ErrorCode.SUCCESS;
    }

    private boolean isValidAuthorityIssuerName(String name) {
        return !StringUtils.isEmpty(name)
                && name.getBytes(StandardCharsets.UTF_8).length
                < maskidConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH
                && !StringUtils.isWhitespace(name);
    }

    @Override
    public ResponseData<String> getmaskidByOrgId(String orgId) {
        if (!isValidAuthorityIssuerName(orgId)) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL);
        }
        try {
            return authEngine.getmaskidFromOrgId(orgId);
        } catch (Exception e) {
            logger.error("Failed to get maskid, Error Message:{}", e);
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }
}
