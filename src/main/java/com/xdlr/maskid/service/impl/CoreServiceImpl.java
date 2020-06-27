package com.xdlr.maskid.service.impl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xdlr.maskid.constant.ErrorCode;
import com.xdlr.maskid.constant.maskidConstant;
import com.xdlr.maskid.exception.LoadContractException;
import com.xdlr.maskid.exception.PrivateKeyIllegalException;
import com.xdlr.maskid.protocol.base.AuthenticationProperty;
import com.xdlr.maskid.protocol.base.PublicKeyProperty;
import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.base.maskidDocument;
import com.xdlr.maskid.protocol.base.maskidPrivateKey;
import com.xdlr.maskid.protocol.base.maskidPublicKey;
import com.xdlr.maskid.protocol.request.AuthenticationArgs;
import com.xdlr.maskid.protocol.request.CreatemaskidArgs;
import com.xdlr.maskid.protocol.request.PublicKeyArgs;
import com.xdlr.maskid.protocol.request.ServiceArgs;
import com.xdlr.maskid.protocol.request.SetAuthenticationArgs;
import com.xdlr.maskid.protocol.request.SetPublicKeyArgs;
import com.xdlr.maskid.protocol.request.SetServiceArgs;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.rpc.maskidService;
import com.xdlr.maskid.util.maskidUtils;

/**
 * Service implementations for operations on maskid.
 *
 * @author xdlr
 */
public class CoreServiceImpl extends AbstractService implements CoreService {

    /**
     * log4j object, for recording log.
     */
    private static final Logger logger = LoggerFactory.getLogger(CoreServiceImpl.class);

    /**
     * Create a maskid with null input param.
     *
     * @return the response data
     */
    @Override
    public ResponseData<CreatemaskidDataResult> createMaskId() {

        CreatemaskidDataResult result = new CreatemaskidDataResult();
        ECKeyPair keyPair = null;

        try {
            keyPair = Keys.createEcKeyPair();
        } catch (Exception e) {
            logger.error("Create maskid failed.", e);
            return new ResponseData<>(null, ErrorCode.maskid_KEYPAIR_CREATE_FAILED);
        }

        String publicKey = String.valueOf(keyPair.getPublicKey());
        String privateKey = String.valueOf(keyPair.getPrivateKey());
        maskidPublicKey usermaskidPublicKey = new maskidPublicKey();
        usermaskidPublicKey.setPublicKey(publicKey);
        result.setUsermaskidPublicKey(usermaskidPublicKey);
        maskidPrivateKey usermaskidPrivateKey = new maskidPrivateKey();
        usermaskidPrivateKey.setPrivateKey(privateKey);
        result.setUsermaskidPrivateKey(usermaskidPrivateKey);
        String maskid = maskidUtils.convertPublicKeyTomaskid(publicKey);
        result.setmaskid(maskid);

        ResponseData<Boolean> innerResp = processCreatemaskid(maskid, publicKey, privateKey, false);
        if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            logger.error(
                    "[createmaskid] Create maskid failed. error message is :{}",
                    innerResp.getErrorMessage()
            );
            return new ResponseData<>(null,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
        }
        return new ResponseData<>(result, ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                innerResp.getTransactionInfo());
    }

    /**
     * Create a maskid.
     *
     * @param createmaskidArgs the create maskid args
     * @return the response data
     */
    @Override
    public ResponseData<String> createMaskId(CreatemaskidArgs createmaskidArgs) {

        if (createmaskidArgs == null) {
            logger.error("[createmaskid]: input parameter createmaskidArgs is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(createmaskidArgs.getmaskidPrivateKey()) || !maskidUtils
                .isPrivateKeyLengthValid(createmaskidArgs.getmaskidPrivateKey().getPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        String privateKey = createmaskidArgs.getmaskidPrivateKey().getPrivateKey();
        String publicKey = createmaskidArgs.getPublicKey();
        if (StringUtils.isNotBlank(publicKey)) {
            if (!maskidUtils.isKeypairMatch(privateKey, publicKey)) {
                return new ResponseData<>(
                        StringUtils.EMPTY,
                        ErrorCode.maskid_PUBLICKEY_AND_PRIVATEKEY_NOT_MATCHED
                );
            }
            String maskid = maskidUtils.convertPublicKeyTomaskid(publicKey);
            ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
            if (ismaskidExistResp.getResult() == null || ismaskidExistResp.getResult()) {
                logger
                        .error("[createmaskid]: create maskid failed, the maskid :{} is already exist", maskid);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreatemaskid(maskid, publicKey, privateKey, false);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                        "[createmaskid]: create maskid failed. error message is :{}, public key is {}",
                        innerResp.getErrorMessage(),
                        publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                        ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                        innerResp.getTransactionInfo());
            }
            return new ResponseData<>(maskid,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_PUBLICKEY_INVALID);
        }
    }

    /**
     * Get a maskid Document.
     *
     * @param maskid the maskid
     * @return the maskid document
     */
    @Override
    public ResponseData<maskidDocument> getmaskidDocument(String maskid) {

        if (!maskidUtils.ismaskidValid(maskid)) {
            logger.error("Input maskid : {} is invalid.", maskid);
            return new ResponseData<>(null, ErrorCode.maskid_INVALID);
        }
        ResponseData<maskidDocument> maskidDocResp = maskidServiceEngine.getmaskidDocument(maskid);
        if (maskidDocResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
            return maskidDocResp;
        }
        return new ResponseData<>(trimObsoletemaskidDocument(maskidDocResp.getResult()),
                maskidDocResp.getErrorCode(), maskidDocResp.getErrorMessage());
    }

    private maskidDocument trimObsoletemaskidDocument(maskidDocument originalDocument) {
        List<PublicKeyProperty> pubKeysToRemove = new ArrayList<>();
        List<AuthenticationProperty> authToRemove = new ArrayList<>();
        for (PublicKeyProperty pr : originalDocument.getPublicKey()) {
            if (pr.getPublicKey().contains(maskidConstant.REMOVED_PUBKEY_TAG)) {
                pubKeysToRemove.add(pr);
                for (AuthenticationProperty ap : originalDocument.getAuthentication()) {
                    if (ap.getPublicKey().equalsIgnoreCase(pr.getId())) {
                        authToRemove.add(ap);
                    }
                }
            }
        }
        for (AuthenticationProperty ap : originalDocument.getAuthentication()) {
            if (ap.getPublicKey().contains(maskidConstant.REMOVED_AUTHENTICATION_TAG)) {
                authToRemove.add(ap);
            }
        }
        originalDocument.getPublicKey().removeAll(pubKeysToRemove);
        originalDocument.getAuthentication().removeAll(authToRemove);
        return originalDocument;
    }

    /**
     * Get a maskid Document Json.
     *
     * @param maskid the maskid
     * @return the maskid document json
     */
    @Override
    public ResponseData<String> getmaskidDocumentJson(String maskid) {

        ResponseData<maskidDocument> responseData = this.getmaskidDocument(maskid);
        maskidDocument result = responseData.getResult();

        if (result == null) {
            return new ResponseData<>(
                    StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        ObjectMapper mapper = new ObjectMapper();
        String maskidDocument;
        try {
            maskidDocument = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (Exception e) {
            logger.error("write object to String fail.", e);
            return new ResponseData<>(
                    StringUtils.EMPTY,
                    ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        maskidDocument =
                new StringBuffer()
                        .append(maskidDocument)
                        .insert(1, maskidConstant.maskid_DOC_PROTOCOL_VERSION)
                        .toString();

        ResponseData<String> responseDataJson = new ResponseData<String>();
        responseDataJson.setResult(maskidDocument);
        responseDataJson.setErrorCode(ErrorCode.getTypeByErrorCode(responseData.getErrorCode()));

        return responseDataJson;
    }

    /**
     * Remove a public key enlisted in maskid document together with the its authentication.
     *
     * @param setPublicKeyArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    @Override
    public ResponseData<Boolean> removePublicKeyWithAuthentication(
            SetPublicKeyArgs setPublicKeyArgs) {
        if (!verifySetPublicKeyArgs(setPublicKeyArgs)) {
            logger.error("[removePublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(setPublicKeyArgs.getUsermaskidPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }

        String maskid = setPublicKeyArgs.getmaskid();
        ResponseData<maskidDocument> responseData = this.getmaskidDocument(maskid);
        if (responseData.getResult() == null) {
            return new ResponseData<>(false,
                    ErrorCode.getTypeByErrorCode(responseData.getErrorCode())
            );
        }
        List<PublicKeyProperty> publicKeys = responseData.getResult().getPublicKey();
        for (PublicKeyProperty pk : publicKeys) {
            // TODO in future, add authorization check
            if (pk.getPublicKey().equalsIgnoreCase(setPublicKeyArgs.getPublicKey())) {
                if (publicKeys.size() == 1) {
                    return new ResponseData<>(false,
                            ErrorCode.maskid_CANNOT_REMOVE_ITS_OWN_PUB_KEY_WITHOUT_BACKUP);
                }
            }
        }

        // Add correct tag by externally call removeAuthentication once
        SetAuthenticationArgs setAuthenticationArgs = new SetAuthenticationArgs();
        setAuthenticationArgs.setmaskid(maskid);
        maskidPrivateKey maskidPrivateKey = new maskidPrivateKey();
        maskidPrivateKey.setPrivateKey(setPublicKeyArgs.getUsermaskidPrivateKey().getPrivateKey());
        setAuthenticationArgs.setUsermaskidPrivateKey(maskidPrivateKey);
        setAuthenticationArgs.setPublicKey(setPublicKeyArgs.getPublicKey());
        setAuthenticationArgs.setOwner(setPublicKeyArgs.getOwner());
        ResponseData<Boolean> removeAuthResp = this.removeAuthentication(setAuthenticationArgs);
        if (!removeAuthResp.getResult()) {
            logger.error("Failed to remove authentication: " + removeAuthResp.getErrorMessage());
            return removeAuthResp;
        }

        String owner = setPublicKeyArgs.getOwner();
        String weAddress = maskidUtils.convertmaskidToAddress(setPublicKeyArgs.getmaskid());

        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (maskidUtils.ismaskidValid(owner)) {
                owner = maskidUtils.convertmaskidToAddress(owner);
            } else {
                logger.error("removePublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.maskid_INVALID);
            }
        }
        try {
            String attributeKey =
                    new StringBuffer()
                            .append(maskidConstant.maskid_DOC_PUBLICKEY_PREFIX)
                            .append(maskidConstant.SEPARATOR)
                            .append(setPublicKeyArgs.getType())
                            .append(maskidConstant.SEPARATOR)
                            .append("base64")
                            .toString();
            String privateKey = setPublicKeyArgs.getUsermaskidPrivateKey().getPrivateKey();
            String publicKey = setPublicKeyArgs.getPublicKey();
            String attrValue = new StringBuffer()
                    .append(publicKey)
                    .append(maskidConstant.REMOVED_PUBKEY_TAG).append("/")
                    .append(owner)
                    .toString();
            return maskidServiceEngine.setAttribute(
                    weAddress,
                    attributeKey,
                    attrValue,
                    privateKey,
                    false);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[removePublicKey] set PublicKey failed because privateKey is illegal. ",
                    e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[removePublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /**
     * Set Public Key.
     *
     * @param setPublicKeyArgs the set public key args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setPublicKey(SetPublicKeyArgs setPublicKeyArgs) {

        if (!verifySetPublicKeyArgs(setPublicKeyArgs)) {
            logger.error("[setPublicKey]: input parameter setPublicKeyArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(setPublicKeyArgs.getUsermaskidPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }

        String maskid = setPublicKeyArgs.getmaskid();
        String weAddress = maskidUtils.convertmaskidToAddress(maskid);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("setPublicKey: maskid : {} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
        ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
        if (ismaskidExistResp.getResult() == null || !ismaskidExistResp.getResult()) {
            logger.error("[SetPublicKey]: failed, the maskid :{} does not exist", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
        }
        String owner = setPublicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (maskidUtils.ismaskidValid(owner)) {
                owner = maskidUtils.convertmaskidToAddress(owner);
            } else {
                logger.error("setPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.maskid_INVALID);
            }
        }
        String pubKey = setPublicKeyArgs.getPublicKey();

        String privateKey = setPublicKeyArgs.getUsermaskidPrivateKey().getPrivateKey();
        return processSetPubKey(
                setPublicKeyArgs.getType().getTypeName(),
                weAddress,
                owner,
                pubKey,
                privateKey,
                false);
    }


    /**
     * Set Service.
     *
     * @param setServiceArgs the set service args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setService(SetServiceArgs setServiceArgs) {
        if (!verifySetServiceArgs(setServiceArgs)) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(setServiceArgs.getUsermaskidPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(setServiceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.maskid_SERVICE_TYPE_OVERLIMIT);
        }
        String maskid = setServiceArgs.getmaskid();
        String serviceType = setServiceArgs.getType();
        String serviceEndpoint = setServiceArgs.getServiceEndpoint();
        return processSetService(
                setServiceArgs.getUsermaskidPrivateKey().getPrivateKey(),
                maskid,
                serviceType,
                serviceEndpoint,
                false);

    }

    /**
     * Check if maskid exists on Chain.
     *
     * @param maskid the maskid
     * @return true if exists, false otherwise
     */
    @Override
    public ResponseData<Boolean> ismaskidExist(String maskid) {
        if (!maskidUtils.ismaskidValid(maskid)) {
            logger.error("[ismaskidExist] check maskid failed. maskid : {} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
        return maskidServiceEngine.ismaskidExist(maskid);
    }

    /**
     * Set Authentication.
     *
     * @param setAuthenticationArgs the set authentication args
     * @return the response data
     */
    @Override
    public ResponseData<Boolean> setAuthentication(SetAuthenticationArgs setAuthenticationArgs) {

        if (!verifySetAuthenticationArgs(setAuthenticationArgs)) {
            logger.error("[setAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(setAuthenticationArgs.getUsermaskidPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        String maskid = setAuthenticationArgs.getmaskid();
        return processSetAuthentication(
                setAuthenticationArgs.getOwner(),
                setAuthenticationArgs.getPublicKey(),
                setAuthenticationArgs.getUsermaskidPrivateKey().getPrivateKey(),
                maskid,
                false);
    }

    private ResponseData<Boolean> processSetAuthentication(
            String owner,
            String publicKey,
            String privateKey,
            String maskid,
            boolean isDelegate) {
        if (maskidUtils.ismaskidValid(maskid)) {
            ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
            if (ismaskidExistResp.getResult() == null || !ismaskidExistResp.getResult()) {
                logger.error("[setAuthentication]: failed, the maskid :{} does not exist",
                        maskid);
                return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
            }
            String weAddress = maskidUtils.convertmaskidToAddress(maskid);
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (maskidUtils.ismaskidValid(owner)) {
                    owner = maskidUtils.convertmaskidToAddress(owner);
                } else {
                    logger.error("[setAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.maskid_INVALID);
                }
            }
            try {
                String attrValue = new StringBuffer()
                        .append(publicKey)
                        .append(maskidConstant.SEPARATOR)
                        .append(owner)
                        .toString();
                return maskidServiceEngine
                        .setAttribute(weAddress,
                                maskidConstant.maskid_DOC_AUTHENTICATE_PREFIX,
                                attrValue,
                                privateKey,
                                isDelegate);
            } catch (PrivateKeyIllegalException e) {
                logger.error("Set authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("Set authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. maskid : {} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
    }

    /**
     * Remove an authentication tag in maskid document only - will not affect its public key.
     *
     * @param setAuthenticationArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    public ResponseData<Boolean> removeAuthentication(SetAuthenticationArgs setAuthenticationArgs) {

        if (!verifySetAuthenticationArgs(setAuthenticationArgs)) {
            logger
                    .error("[removeAuthentication]: input parameter setAuthenticationArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(setAuthenticationArgs.getUsermaskidPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        String maskid = setAuthenticationArgs.getmaskid();
        if (maskidUtils.ismaskidValid(maskid)) {
            ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
            if (ismaskidExistResp.getResult() == null || !ismaskidExistResp.getResult()) {
                logger.error("[SetAuthentication]: failed, the maskid :{} does not exist", maskid);
                return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
            }
            String weAddress = maskidUtils.convertmaskidToAddress(maskid);

            String owner = setAuthenticationArgs.getOwner();
            if (StringUtils.isEmpty(owner)) {
                owner = weAddress;
            } else {
                if (maskidUtils.ismaskidValid(owner)) {
                    owner = maskidUtils.convertmaskidToAddress(owner);
                } else {
                    logger.error("[removeAuthentication]: owner : {} is invalid.", owner);
                    return new ResponseData<>(false, ErrorCode.maskid_INVALID);
                }
            }
            String privateKey = setAuthenticationArgs.getUsermaskidPrivateKey().getPrivateKey();
            try {
                String attrValue = new StringBuffer()
                        .append(setAuthenticationArgs.getPublicKey())
                        .append(maskidConstant.REMOVED_AUTHENTICATION_TAG)
                        .append(maskidConstant.SEPARATOR)
                        .append(owner)
                        .toString();
                return maskidServiceEngine
                        .setAttribute(weAddress,
                                maskidConstant.maskid_DOC_AUTHENTICATE_PREFIX,
                                attrValue,
                                privateKey,
                                false);
            } catch (PrivateKeyIllegalException e) {
                logger
                        .error("remove authenticate with private key exception. Error message :{}", e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("remove authenticate failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("Set authenticate failed. maskid : {} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
    }

    private boolean verifySetServiceArgs(SetServiceArgs setServiceArgs) {

        return !(setServiceArgs == null
                || StringUtils.isBlank(setServiceArgs.getType())
                || setServiceArgs.getUsermaskidPrivateKey() == null
                || StringUtils.isBlank(setServiceArgs.getServiceEndpoint()));
    }

    private boolean verifyServiceType(String type) {
        String serviceType = new StringBuffer()
                .append(maskidConstant.maskid_DOC_SERVICE_PREFIX)
                .append(maskidConstant.SEPARATOR)
                .append(type)
                .toString();
        int serviceTypeLength = serviceType.getBytes(StandardCharsets.UTF_8).length;
        return serviceTypeLength <= maskidConstant.BYTES32_FIXED_LENGTH;
    }

    private ResponseData<Boolean> processCreatemaskid(
            String maskid,
            String publicKey,
            String privateKey,
            boolean isDelegate) {

        String address = maskidUtils.convertmaskidToAddress(maskid);
        try {
            return maskidServiceEngine.createmaskid(address, publicKey, privateKey, isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[createmaskid] create maskid failed because privateKey is illegal. ",
                    e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (LoadContractException e) {
            logger.error("[createmaskid] create maskid failed because Load Contract with "
                            + "exception. ",
                    e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[createmaskid] create maskid failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    private boolean verifySetPublicKeyArgs(SetPublicKeyArgs setPublicKeyArgs) {

        return !(setPublicKeyArgs == null
                || setPublicKeyArgs.getType() == null
                || setPublicKeyArgs.getUsermaskidPrivateKey() == null
                || StringUtils.isBlank(setPublicKeyArgs.getPublicKey()));
    }

    private boolean verifySetAuthenticationArgs(SetAuthenticationArgs setAuthenticationArgs) {

        return !(setAuthenticationArgs == null
                || setAuthenticationArgs.getUsermaskidPrivateKey() == null
                || StringUtils.isEmpty(setAuthenticationArgs.getPublicKey()));
    }

    /* (non-Javadoc)
     * @see com.xdlr.maskid.rpc.maskidService#delegateCreatemaskid(
     * com.xdlr.maskid.protocol.base.maskidPublicKey,
     * com.xdlr.maskid.protocol.base.maskidAuthentication)
     */
    @Override
    public ResponseData<String> delegateCreatemaskid(
            maskidPublicKey publicKey,
            maskidAuthentication maskidAuthentication) {

        if (publicKey == null || maskidAuthentication == null) {
            logger.error("[delegateCreatemaskid]: input parameter is null.");
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(maskidAuthentication.getmaskidPrivateKey())) {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        String privateKey = maskidAuthentication.getmaskidPrivateKey().getPrivateKey();
        String pubKey = publicKey.getPublicKey();
        if (StringUtils.isNotBlank(pubKey) && NumberUtils.isDigits(pubKey)) {
            String maskid = maskidUtils.convertPublicKeyTomaskid(pubKey);
            ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
            if (ismaskidExistResp.getResult() == null || ismaskidExistResp.getResult()) {
                logger
                        .error(
                                "[delegateCreatemaskid]: create maskid failed, the maskid :{} is already exist",
                                maskid);
                return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_ALREADY_EXIST);
            }
            ResponseData<Boolean> innerResp = processCreatemaskid(maskid, pubKey, privateKey, true);
            if (innerResp.getErrorCode() != ErrorCode.SUCCESS.getCode()) {
                logger.error(
                        "[delegateCreatemaskid]: create maskid failed. error message is :{}, "
                                + "public key is {}",
                        innerResp.getErrorMessage(),
                        publicKey
                );
                return new ResponseData<>(StringUtils.EMPTY,
                        ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                        innerResp.getTransactionInfo());
            }
            return new ResponseData<>(maskid,
                    ErrorCode.getTypeByErrorCode(innerResp.getErrorCode()),
                    innerResp.getTransactionInfo());
        } else {
            return new ResponseData<>(StringUtils.EMPTY, ErrorCode.maskid_PUBLICKEY_INVALID);
        }
    }

    /* (non-Javadoc)
     * @see com.xdlr.maskid.rpc.maskidService#delegateSetPublicKey(
     * com.xdlr.maskid.protocol.request.PublicKeyArgs,
     * com.xdlr.maskid.protocol.base.maskidAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetPublicKey(
            PublicKeyArgs publicKeyArgs,
            maskidAuthentication delegateAuth) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (publicKeyArgs == null || StringUtils.isEmpty(publicKeyArgs.getPublicKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PUBLICKEY_INVALID);
        }
        if (!maskidUtils.isPrivateKeyValid(delegateAuth.getmaskidPrivateKey()) || !maskidUtils
                .isPrivateKeyLengthValid(delegateAuth.getmaskidPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }

        String maskid = publicKeyArgs.getmaskid();
        ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
        if (ismaskidExistResp.getResult() == null || !ismaskidExistResp.getResult()) {
            logger.error("[SetPublicKey]: failed, the maskid :{} does not exist", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
        }
        String weAddress = maskidUtils.convertmaskidToAddress(maskid);
        if (StringUtils.isEmpty(weAddress)) {
            logger.error("setPublicKey: maskid : {} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
        String owner = publicKeyArgs.getOwner();
        if (StringUtils.isEmpty(owner)) {
            owner = weAddress;
        } else {
            if (maskidUtils.ismaskidValid(owner)) {
                owner = maskidUtils.convertmaskidToAddress(owner);
            } else {
                logger.error("setPublicKey: owner : {} is invalid.", owner);
                return new ResponseData<>(false, ErrorCode.maskid_INVALID);
            }
        }
        String pubKey = publicKeyArgs.getPublicKey();

        String privateKey = delegateAuth.getmaskidPrivateKey().getPrivateKey();

        return processSetPubKey(
                publicKeyArgs.getType().getTypeName(),
                weAddress,
                owner,
                pubKey,
                privateKey,
                true);
    }

    private ResponseData<Boolean> processSetPubKey(
            String type,
            String weAddress,
            String owner,
            String pubKey,
            String privateKey,
            boolean isDelegate) {

        try {
            String attributeKey =
                    new StringBuffer()
                            .append(maskidConstant.maskid_DOC_PUBLICKEY_PREFIX)
                            .append(maskidConstant.SEPARATOR)
                            .append(type)
                            .append(maskidConstant.SEPARATOR)
                            .append("base64")
                            .toString();
            String attrValue = new StringBuffer().append(pubKey).append("/").append(owner)
                    .toString();
            return maskidServiceEngine.setAttribute(
                    weAddress,
                    attributeKey,
                    attrValue,
                    privateKey,
                    isDelegate);
        } catch (PrivateKeyIllegalException e) {
            logger.error("[setPublicKey] set PublicKey failed because privateKey is illegal. ",
                    e);
            return new ResponseData<>(false, e.getErrorCode());
        } catch (Exception e) {
            logger.error("[setPublicKey] set PublicKey failed with exception. ", e);
            return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
        }
    }

    /* (non-Javadoc)
     * @see com.xdlr.maskid.rpc.maskidService#delegateSetService(
     * com.xdlr.maskid.protocol.request.SetServiceArgs,
     * com.xdlr.maskid.protocol.base.maskidAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetService(
            ServiceArgs serviceArgs,
            maskidAuthentication delegateAuth) {
        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (serviceArgs == null || StringUtils.isEmpty(serviceArgs.getServiceEndpoint())
                || !maskidUtils.ismaskidValid(serviceArgs.getmaskid())) {
            logger.error("[setService]: input parameter setServiceArgs is illegal.");
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(delegateAuth.getmaskidPrivateKey()) || !maskidUtils
                .isPrivateKeyLengthValid(delegateAuth.getmaskidPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        if (!verifyServiceType(serviceArgs.getType())) {
            logger.error("[setService]: the length of service type is overlimit");
            return new ResponseData<>(false, ErrorCode.maskid_SERVICE_TYPE_OVERLIMIT);
        }
        String maskid = serviceArgs.getmaskid();
        String serviceType = serviceArgs.getType();
        String serviceEndpoint = serviceArgs.getServiceEndpoint();
        return processSetService(
                delegateAuth.getmaskidPrivateKey().getPrivateKey(),
                maskid,
                serviceType,
                serviceEndpoint,
                true);
    }

    private ResponseData<Boolean> processSetService(
            String privateKey,
            String maskid,
            String serviceType,
            String serviceEndpoint,
            boolean isDelegate) {
        if (maskidUtils.ismaskidValid(maskid)) {
            ResponseData<Boolean> ismaskidExistResp = this.ismaskidExist(maskid);
            if (ismaskidExistResp.getResult() == null || !ismaskidExistResp.getResult()) {
                logger.error("[SetService]: failed, the maskid :{} does not exist", maskid);
                return new ResponseData<>(false, ErrorCode.maskid_DOES_NOT_EXIST);
            }
            try {
                String attributeKey = new StringBuffer()
                        .append(maskidConstant.maskid_DOC_SERVICE_PREFIX)
                        .append(maskidConstant.SEPARATOR)
                        .append(serviceType)
                        .toString();
                return maskidServiceEngine
                        .setAttribute(
                                maskidUtils.convertmaskidToAddress(maskid),
                                attributeKey,
                                serviceEndpoint,
                                privateKey,
                                isDelegate);

            } catch (PrivateKeyIllegalException e) {
                logger
                        .error("[setService] set PublicKey failed because privateKey is illegal. ",
                                e);
                return new ResponseData<>(false, e.getErrorCode());
            } catch (Exception e) {
                logger.error("[setService] set service failed. Error message :{}", e);
                return new ResponseData<>(false, ErrorCode.UNKNOW_ERROR);
            }
        } else {
            logger.error("[setService] set service failed, maskid -->{} is invalid.", maskid);
            return new ResponseData<>(false, ErrorCode.maskid_INVALID);
        }
    }

    /* (non-Javadoc)
     * @see com.xdlr.maskid.rpc.maskidService#delegateSetAuthentication(
     * com.xdlr.maskid.protocol.request.SetAuthenticationArgs,
     * com.xdlr.maskid.protocol.base.maskidAuthentication)
     */
    @Override
    public ResponseData<Boolean> delegateSetAuthentication(
            AuthenticationArgs authenticationArgs,
            maskidAuthentication delegateAuth) {

        if (delegateAuth == null) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (authenticationArgs == null || !maskidUtils.ismaskidValid(authenticationArgs.getmaskid())
                || StringUtils.isEmpty(authenticationArgs.getPublicKey())) {
            return new ResponseData<>(false, ErrorCode.ILLEGAL_INPUT);
        }
        if (!maskidUtils.isPrivateKeyValid(delegateAuth.getmaskidPrivateKey()) || !maskidUtils
                .isPrivateKeyLengthValid(delegateAuth.getmaskidPrivateKey().getPrivateKey())) {
            return new ResponseData<>(false, ErrorCode.maskid_PRIVATEKEY_INVALID);
        }
        String maskid = authenticationArgs.getmaskid();
        return processSetAuthentication(
                authenticationArgs.getOwner(),
                authenticationArgs.getPublicKey(),
                delegateAuth.getmaskidPrivateKey().getPrivateKey(),
                maskid,
                true);
    }
}
