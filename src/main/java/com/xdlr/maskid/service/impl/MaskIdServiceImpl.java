package com.xdlr.maskid.service.impl;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.xdlr.maskid.constant.ErrorCode;
import com.xdlr.maskid.demo.common.util.FileUtil;
import com.xdlr.maskid.demo.common.util.PrivateKeyUtil;
import com.xdlr.maskid.demo.service.DemoService;
import com.xdlr.maskid.protocol.base.AuthorityIssuer;
import com.xdlr.maskid.protocol.base.CptBaseInfo;
import com.xdlr.maskid.protocol.base.Credential;
import com.xdlr.maskid.protocol.base.CredentialWrapper;
import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.base.maskidPrivateKey;
import com.xdlr.maskid.protocol.request.CptMapArgs;
import com.xdlr.maskid.protocol.request.CreateCredentialArgs;
import com.xdlr.maskid.protocol.request.CreatemaskidArgs;
import com.xdlr.maskid.protocol.request.RegisterAuthorityIssuerArgs;
import com.xdlr.maskid.protocol.request.SetAuthenticationArgs;
import com.xdlr.maskid.protocol.request.SetPublicKeyArgs;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;
import com.xdlr.maskid.rpc.AuthorityIssuerService;
import com.xdlr.maskid.rpc.CptService;
import com.xdlr.maskid.rpc.CredentialService;
import com.xdlr.maskid.rpc.maskidService;
import com.xdlr.maskid.service.impl.AuthorityIssuerServiceImpl;
import com.xdlr.maskid.service.impl.CptServiceImpl;
import com.xdlr.maskid.service.impl.CredentialServiceImpl;
import com.xdlr.maskid.service.impl.maskidServiceImpl;
import com.xdlr.maskid.util.DataToolUtils;

/**
 * Demo service.
 *
 * @author xdlr
 */
@Service
public class MaskIdServiceImpl implements MaskIdService {

    private static final Logger logger = LoggerFactory.getLogger(MaskIdServiceImpl.class);

    private AuthorityIssuerService authorityIssuerService = new AuthorityIssuerServiceImpl();

    private CptService cptService = new CptServiceImpl();

    private CredentialService credentialService = new CredentialServiceImpl();

    private CoreService coreService = new CoreServiceImpl();

    /**
     * set validity period to 360 days by default.
     */
    private static final long EXPIRATION_DATE  = 1000L * 60 * 60 * 24 * 365 * 100;


    /**
     * create maskid with public and private keys and set related properties.
     *
     * @param publicKey public key
     * @param privateKey private key
     * @return returns the create maskid
     */
    public ResponseData<String> createmaskidAndSetAttr(String publicKey, String privateKey) {

        logger.info("begin create maskid and set attribute without parameter");

        // 1, create maskid using the incoming public and private keys
        CreatemaskidArgs createmaskidArgs = new CreatemaskidArgs();
        createmaskidArgs.setPublicKey(publicKey);
        createmaskidArgs.setmaskidPrivateKey(new maskidPrivateKey());
        createmaskidArgs.getmaskidPrivateKey().setPrivateKey(privateKey);
        ResponseData<String> createResult = maskidService.createmaskid(createmaskidArgs);
        logger.info("createmaskidAndSetAttr response:{}", createResult);
        if (createResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            return createResult;
        }

        PrivateKeyUtil.savePrivateKey(
                PrivateKeyUtil.KEY_DIR,
                createResult.getResult(),
                privateKey
        );

        return createResult;
    }


    /**
     * 创建maskid.
     * @return
     */
    public ResponseData<CreatemaskidDataResult> createmaskid() {

        ResponseData<CreatemaskidDataResult> response = createmaskidWithSetAttr();
        // if maskid is created successfully, save its private key.
        if (response.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {
            PrivateKeyUtil.savePrivateKey(
                    PrivateKeyUtil.KEY_DIR,
                    response.getResult().getmaskid(),
                    response.getResult().getUsermaskidPrivateKey().getPrivateKey()
            );
        }

        /*
         *  private keys are not allowed to be transmitted over http, so this place
         *  annotates the return of private keys to avoid misuse.
         */
        response.getResult().setUsermaskidPrivateKey(null);
        return response;
    }

    /**
     * create maskid and set related properties.
     *
     * @return returns the create maskid and public private keys
     */
    private ResponseData<CreatemaskidDataResult> createmaskidWithSetAttr() {

        logger.info("begin create maskid and set attribute");

        // 1, create maskid, this method automatically creates public and private keys
        ResponseData<CreatemaskidDataResult> createResult = maskidService.createmaskid();
        logger.info(
                "maskidService is result,errorCode:{},errorMessage:{}",
                createResult.getErrorCode(), createResult.getErrorMessage()
        );

        if (createResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            return createResult;
        }

        // 2, call set public key
        ResponseData<Boolean> setPublicKeyRes = this.setPublicKey(createResult.getResult());
        if (!setPublicKeyRes.getResult()) {
            createResult.setErrorCode(
                    ErrorCode.getTypeByErrorCode(setPublicKeyRes.getErrorCode())
            );
            return createResult;
        }

        // 3, call set authentication
        ResponseData<Boolean> setAuthenticateRes = this.setAuthentication(createResult.getResult());
        if (!setAuthenticateRes.getResult()) {
            createResult.setErrorCode(
                    ErrorCode.getTypeByErrorCode(setAuthenticateRes.getErrorCode())
            );
            return createResult;
        }
        return createResult;
    }

    /**
     * Set Public Key For maskid Document.
     *
     * @param createmaskidDataResult the object of CreatemaskidDataResult
     * @return the response data
     */
    private ResponseData<Boolean> setPublicKey(CreatemaskidDataResult createmaskidDataResult) {

        // build setPublicKey parameters.
        SetPublicKeyArgs setPublicKeyArgs = new SetPublicKeyArgs();
        setPublicKeyArgs.setmaskid(createmaskidDataResult.getmaskid());
        setPublicKeyArgs.setPublicKey(createmaskidDataResult.getUsermaskidPublicKey().getPublicKey());
        setPublicKeyArgs.setUsermaskidPrivateKey(new maskidPrivateKey());
        setPublicKeyArgs.getUsermaskidPrivateKey()
                .setPrivateKey(createmaskidDataResult.getUsermaskidPrivateKey().getPrivateKey());

        // call SDK method to chain set attribute.
        ResponseData<Boolean> setResponse = maskidService.setPublicKey(setPublicKeyArgs);
        logger.info(
                "setPublicKey is result,errorCode:{},errorMessage:{}",
                setResponse.getErrorCode(),
                setResponse.getErrorMessage()
        );
        return setResponse;
    }

    /**
     * Set Authentication For maskid Document.
     *
     * @param createmaskidDataResult createmaskidDataResult the object of CreatemaskidDataResult
     * @return the response data
     */
    private ResponseData<Boolean> setAuthentication(CreatemaskidDataResult createmaskidDataResult) {

        // build setAuthentication parameters.
        SetAuthenticationArgs setAuthenticationArgs = new SetAuthenticationArgs();
        setAuthenticationArgs.setmaskid(createmaskidDataResult.getmaskid());
        setAuthenticationArgs
                .setPublicKey(createmaskidDataResult.getUsermaskidPublicKey().getPublicKey());
        setAuthenticationArgs.setUsermaskidPrivateKey(new maskidPrivateKey());
        setAuthenticationArgs.getUsermaskidPrivateKey()
                .setPrivateKey(createmaskidDataResult.getUsermaskidPrivateKey().getPrivateKey());

        // call SDK method to chain set attribute.
        ResponseData<Boolean> setResponse = maskidService.setAuthentication(setAuthenticationArgs);
        logger.info(
                "setAuthentication is result,errorCode:{},errorMessage:{}",
                setResponse.getErrorCode(),
                setResponse.getErrorMessage()
        );
        return setResponse;
    }

    /**
     * register on the chain as an authoritative body.
     *
     * @param authorityName the name of the issue
     * @return true is success, false is failure
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(String issuer, String authorityName) {

        // build registerAuthorityIssuer parameters.
        AuthorityIssuer authorityIssuerResult = new AuthorityIssuer();
        authorityIssuerResult.setmaskid(issuer);
        authorityIssuerResult.setName(authorityName);
        authorityIssuerResult.setAccValue("0");

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs.setAuthorityIssuer(authorityIssuerResult);
        registerAuthorityIssuerArgs.setmaskidPrivateKey(new maskidPrivateKey());

        // getting SDK private key from file.
        String privKey = FileUtil.getDataByPath(PrivateKeyUtil.SDK_PRIVKEY_PATH);

        registerAuthorityIssuerArgs.getmaskidPrivateKey().setPrivateKey(privKey);

        ResponseData<Boolean> registResponse =
                authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        logger.info(
                "registerAuthorityIssuer is result,errorCode:{},errorMessage:{}",
                registResponse.getErrorCode(),
                registResponse.getErrorMessage()
        );
        return registResponse;
    }

    /**
     * registered CPT.
     *
     * @param publisher the maskid of the publisher
     * @param privateKey the private key of the publisher
     * @param claim claim is CPT
     * @return returns cptBaseInfo
     */
    @Override
    public ResponseData<CptBaseInfo> registCpt(
            String publisher,
            String privateKey,
            Map<String, Object> claim) {

        // build registerCpt parameters.
        maskidAuthentication maskidAuthentication = new maskidAuthentication();
        maskidAuthentication.setmaskid(publisher);
        maskidAuthentication.setmaskidPrivateKey(new maskidPrivateKey());
        maskidAuthentication.getmaskidPrivateKey().setPrivateKey(privateKey);

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setmaskidAuthentication(maskidAuthentication);
        cptMapArgs.setCptJsonSchema(claim);

        // create CPT by SDK
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info(
                "registerCpt is result,errorCode:{},errorMessage:{}",
                response.getErrorCode(),
                response.getErrorMessage()
        );
        return response;
    }

    /**
     * create credential.
     *
     * @param cptId the cptId of CPT
     * @param issuer the maskid of issue
     * @param privateKey the private key of issuer
     * @param claimDate the data of claim
     * @return returns credential
     */
    @Override
    public ResponseData<CredentialWrapper> createCredential(
            Integer cptId,
            String issuer,
            String privateKey,
            Map<String, Object> claimDate) {

        // build createCredential parameters.
        CreateCredentialArgs registerCptArgs = new CreateCredentialArgs();
        registerCptArgs.setCptId(cptId);
        registerCptArgs.setIssuer(issuer);
        registerCptArgs.setmaskidPrivateKey(new maskidPrivateKey());
        registerCptArgs.getmaskidPrivateKey().setPrivateKey(privateKey);
        registerCptArgs.setClaim(claimDate);

        // the validity period is 360 days
        registerCptArgs
                .setExpirationDate(System.currentTimeMillis() + EXPIRATION_DATE);

        // create credentials by SDK.
        ResponseData<CredentialWrapper> response =
                credentialService.createCredential(registerCptArgs);
        logger.info(
                "createCredential is result,errorCode:{},errorMessage:{}",
                response.getErrorCode(),
                response.getErrorMessage()
        );
        return response;
    }

    /**
     * verifyEvidence credential.
     *
     * @param credentialJson credentials in JSON format
     * @return returns the result of verifyEvidence
     */
    @Override
    public ResponseData<Boolean> verifyCredential(String credentialJson) {

        ResponseData<Boolean> verifyResponse = null;

        Credential credential = DataToolUtils.deserialize(credentialJson, Credential.class);
        // verifyEvidence credential on chain.
        verifyResponse = credentialService.verify(credential);
        logger.info(
                "verifyCredential is result,errorCode:{},errorMessage:{}",
                verifyResponse.getErrorCode(),
                verifyResponse.getErrorMessage()
        );
        return verifyResponse;
    }
}
