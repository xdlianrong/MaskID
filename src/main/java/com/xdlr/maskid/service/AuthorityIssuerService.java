package com.xdlr.maskid.service;

import java.util.List;

import com.xdlr.maskid.protocol.base.AuthorityIssuer;
import com.xdlr.maskid.protocol.base.maskidAuthentication;
import com.xdlr.maskid.protocol.request.RegisterAuthorityIssuerArgs;
import com.xdlr.maskid.protocol.request.RemoveAuthorityIssuerArgs;
import com.xdlr.maskid.protocol.response.ResponseData;

/**
 * Service inf for operations on Authority Issuer.
 *
 * @author xdlr
 */
public interface AuthorityIssuerService {

    ResponseData<Boolean> registerAuthorityIssuer(RegisterAuthorityIssuerArgs args);

    /**
     * Remove a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return true if succeeds, false otherwise
     */
    ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args);

    /**
     * Check whether the given maskid is an authority issuer, or not.
     *
     * @param maskid the maskid
     * @return true if yes, false otherwise
     */
    ResponseData<Boolean> isAuthorityIssuer(String maskid);

    /**
     * Query the authority issuer information from a given maskid.
     *
     * @param maskid the maskid
     * @return authority issuer info
     */
    ResponseData<AuthorityIssuer> queryAuthorityIssuerInfo(String maskid);

    /**
     * Get all of the authority issuer.
     *
     * @param index start position
     * @param num number of returned authority issuer in this request
     * @return Execution result
     */
    ResponseData<List<AuthorityIssuer>> getAllAuthorityIssuerList(Integer index, Integer num);

    /**
     * Register a new issuer type.
     *
     * @param callerAuth the caller
     * @param issuerType the specified issuer type
     * @return Execution result
     */
    ResponseData<Boolean> registerIssuerType(maskIdAuthentication callerAuth, String issuerType);

    /**
     * Marked an issuer as the specified issuer type.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuermaskid the maskid of the issuer who will be marked as a specific issuer type
     * @return Execution result
     */
    ResponseData<Boolean> addIssuerIntoIssuerType(
            maskidAuthentication callerAuth,
            String issuerType,
            String targetIssuermaskid
    );

    /**
     * Removed an issuer from the specified issuer list.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuermaskid the maskid of the issuer to be removed from a specific issuer list
     * @return Execution result
     */
    ResponseData<Boolean> removeIssuerFromIssuerType(
            maskidAuthentication callerAuth,
            String issuerType,
            String targetIssuermaskid
    );

    /**
     * Check if the given maskid is belonging to a specific issuer type.
     *
     * @param issuerType the issuer type
     * @param targetIssuermaskid the maskid
     * @return true if yes, false otherwise
     */
    ResponseData<Boolean> isSpecificTypeIssuer(
            String issuerType,
            String targetIssuermaskid
    );

    /**
     * Get all specific typed issuer in a list.
     *
     * @param issuerType the issuer type
     * @param index the start position index
     * @param num the number of issuers
     * @return the list
     */
    ResponseData<List<String>> getAllSpecificTypeIssuerList(
            String issuerType,
            Integer index,
            Integer num
    );

    /**
     * Get an issuer's maskid from its name (org ID).
     *
     * @param orgId the org id
     * @return maskid
     */
    ResponseData<String> getmaskidByOrgId(String orgId);
}
