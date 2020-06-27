package com.xdlr.maskid.service;

import com.xdlr.wedpr.selectivedisclosure.CredentialTemplateEntity;

import com.xdlr.maskid.protocol.base.Cpt;
import com.xdlr.maskid.protocol.base.CptBaseInfo;
import com.xdlr.maskid.protocol.request.CptMapArgs;
import com.xdlr.maskid.protocol.request.CptStringArgs;
import com.xdlr.maskid.protocol.response.ResponseData;

/**
 * Service inf for operation on CPT (Claim protocol Type).
 *
 * @author xdlr
 */
public interface CptService {

    /**
     * Register a new CPT to the blockchain.
     *
     * @param args the args
     * @return The registered CPT info
     */
    ResponseData<CptBaseInfo> registerCpt(CptMapArgs args);

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return The registered CPT info
     */
    ResponseData<CptBaseInfo> registerCpt(CptMapArgs args, Integer cptId);

    /**
     * Register a new CPT to the blockchain.
     *
     * @param args the args
     * @return The registered CPT info
     */
    ResponseData<CptBaseInfo> registerCpt(CptStringArgs args);

    /**
     * Register a new CPT with a pre-set CPT ID, to the blockchain.
     *
     * @param args the args
     * @param cptId the CPT ID
     * @return The registered CPT info
     */
    ResponseData<CptBaseInfo> registerCpt(CptStringArgs args, Integer cptId);

    /**
     * Query the latest CPT version.
     *
     * @param cptId the cpt id
     * @return The registered CPT info
     */
    ResponseData<Cpt> queryCpt(Integer cptId);

    /**
     * Update the data fields of a registered CPT.
     *
     * @param args the args
     * @param cptId the cpt id
     * @return The updated CPT info
     */
    ResponseData<CptBaseInfo> updateCpt(CptMapArgs args, Integer cptId);

    /**
     * Update the data fields of a registered CPT.
     *
     * @param args the args
     * @param cptId the cpt id
     * @return The updated CPT info
     */
    ResponseData<CptBaseInfo> updateCpt(CptStringArgs args, Integer cptId);

    /**
     * Update the data fields of a registered CPT.
     *
     * @param cptId the cpt id
     * @return The updated CPT info
     */
    ResponseData<CredentialTemplateEntity> queryCredentialTemplate(Integer cptId);
}
