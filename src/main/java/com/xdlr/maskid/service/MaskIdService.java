package com.xdlr.maskid.service;

import java.util.Map;

import com.xdlr.maskid.protocol.base.CptBaseInfo;
import com.xdlr.maskid.protocol.base.CredentialWrapper;
import com.xdlr.maskid.protocol.response.CreatemaskidDataResult;
import com.xdlr.maskid.protocol.response.ResponseData;

/**
 * demo interface.
 *
 * @author xdlr
 *
 */
public interface MaskIdService {

    /**
     * create maskId with public and private keys and set related properties.
     *
     * @param publicKey public key
     * @param privateKey private key
     * @return returns the create maskid
     */
    ResponseData<String> createMaskIdAndSetAttr(String publicKey, String privateKey);

    /**
     * create maskid and set related properties.
     *
     * @return returns the create maskid  and public private keys
     */
    ResponseData<CreatemaskidDataResult> createMaskId();

    /**
     * register on the chain as an authoritative body.
     *
     * @param authorityName the name of the issue
     * @return true is success, false is failure
     */
    ResponseData<Boolean> registerAuthorityIssuer(String issuer, String authorityName);

    /**
     * registered CPT.
     *
     * @param publisher the maskid of the publisher
     * @param privateKey the private key of the publisher
     * @param claim claim is CPT
     * @return returns cptBaseInfo
     */
    ResponseData<CptBaseInfo> registCpt(
            String publisher,
            String privateKey,
            Map<String, Object> claim
    );

    /**
     * create credential.
     *
     * @param cptId the cptId of CPT
     * @param issuer the maskid of issue
     * @param privateKey the private key of issuer
     * @param claimDate the data of claim
     * @return returns credential
     */
    ResponseData<CredentialWrapper> createCredential(
            Integer cptId,
            String issuer,
            String privateKey,
            Map<String, Object> claimDate
    );

    /**
     * verifyEvidence credential.
     *
     * @param credentialJson credentials in JSON format
     * @return returns the result of verifyEvidence
     */
    ResponseData<Boolean> verifyCredential(String credentialJson);
}
