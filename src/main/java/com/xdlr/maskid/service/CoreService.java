package com.xdlr.maskid.service;

import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.base.maskidDocument;
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


/**
 * Service inf for operations on maskid.
 *
 * @author xdlr
 */
public interface CoreService {

    /**
     * Create a maskid without a keypair. SDK will generate a keypair for the caller.
     *
     * @return a data set including a maskid and a keypair
     */
    ResponseData<CreatemaskidDataResult> createMaskId();

    /**
     * Create a maskid from the provided public key.
     *
     * @param createmaskidArgs you need to input a public key
     * @return maskid
     */
    ResponseData<String> createMaskId(CreatemaskidArgs createmaskidArgs);

    /**
     * Create a maskid from the provided public key.
     *
     * @param publicKey the public key to create a maskid
     * @param maskidAuthentication your private key
     * @return maskid
     */
    ResponseData<String> delegateCreatemaskid(
            maskidPublicKey publicKey,
            maskidAuthentication maskidAuthentication
    );

    /**
     * Query maskid document.
     *
     * @param maskid the maskid
     * @return maskidentity document in json type
     */
    ResponseData<String> getmaskidDocumentJson(String maskid);

    /**
     * Query maskid document.
     *
     * @param maskid the maskid
     * @return maskid document in java object type
     */
    ResponseData<maskidDocument> getmaskidDocument(String maskid);

    /**
     * Set public key in the maskid Document.
     *
     * @param setPublicKeyArgs the set public key args
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> setPublicKey(SetPublicKeyArgs setPublicKeyArgs);

    /**
     * Set public key in the maskid Document.
     *
     * @param publicKeyArgs the set public key args
     * @param delegateAuth the delegate's auth
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> delegateSetPublicKey(
            PublicKeyArgs publicKeyArgs,
            maskidAuthentication delegateAuth
    );

    /**
     * Set service properties.
     *
     * @param setServiceArgs your service name and endpoint
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> setService(SetServiceArgs setServiceArgs);

    /**
     * Set service properties.
     *
     * @param serviceArgs your service name and endpoint
     * @param delegateAuth the delegate's auth
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> delegateSetService(
            ServiceArgs serviceArgs,
            maskidAuthentication delegateAuth
    );

    /**
     * Set authentications in maskid.
     *
     * @param setAuthenticationArgs A public key is needed.
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> setAuthentication(SetAuthenticationArgs setAuthenticationArgs);

    /**
     * Set authentications in maskid.
     *
     * @param authenticationArgs A public key is needed.
     * @param delegateAuth the delegate's auth
     * @return true if the "set" operation succeeds, false otherwise.
     */
    ResponseData<Boolean> delegateSetAuthentication(
            AuthenticationArgs authenticationArgs,
            maskidAuthentication delegateAuth
    );

    /**
     * Check if the maskid exists on chain.
     *
     * @param maskid The maskid.
     * @return true if exists, false otherwise.
     */
    ResponseData<Boolean> ismaskidExist(String maskid);

    /**
     * Remove a public key enlisted in maskid document together with the its authentication.
     *
     * @param setPublicKeyArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    ResponseData<Boolean> removePublicKeyWithAuthentication(SetPublicKeyArgs setPublicKeyArgs);

    /**
     * Remove an authentication tag in maskid document only - will not affect its public key.
     *
     * @param setAuthenticationArgs the to-be-deleted publicKey
     * @return true if succeeds, false otherwise
     */
    ResponseData<Boolean> removeAuthentication(SetAuthenticationArgs setAuthenticationArgs);
}
