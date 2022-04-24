/*
*  Copyright (c) 2005-2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.appmgt.impl;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.Constants;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.appmgt.api.APIProvider;
import org.wso2.carbon.appmgt.api.AppManagementException;
import org.wso2.carbon.appmgt.api.model.APIIdentifier;
import org.wso2.carbon.appmgt.api.model.APPLifecycleActions;
import org.wso2.carbon.appmgt.api.model.App;
import org.wso2.carbon.appmgt.api.model.FileContent;
import org.wso2.carbon.appmgt.api.model.MobileApp;
import org.wso2.carbon.appmgt.api.model.OneTimeDownloadLink;
import org.wso2.carbon.appmgt.api.model.Provider;
import org.wso2.carbon.appmgt.api.model.Tier;
import org.wso2.carbon.appmgt.api.model.Usage;
import org.wso2.carbon.appmgt.impl.dto.Environment;
import org.wso2.carbon.appmgt.impl.dto.TierPermissionDTO;
import org.wso2.carbon.appmgt.impl.service.ServiceReferenceHolder;
import org.wso2.carbon.appmgt.impl.utils.AppManagerUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.governance.api.exception.GovernanceException;
import org.wso2.carbon.governance.api.generic.GenericArtifactManager;
import org.wso2.carbon.governance.api.generic.dataobjects.GenericArtifact;
import org.wso2.carbon.governance.api.util.GovernanceUtils;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.realm.RegistryAuthorizationManager;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.registry.core.utils.RegistryUtils;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * This class provides the core WebApp provider functionality. It is implemented in a very
 * self-contained and 'pure' manner, without taking requirements like security into account,
 * which are subject to frequent change. Due to this 'pure' nature and the significance of
 * the class to the overall WebApp management functionality, the visibility of the class has
 * been reduced to package level. This means we can still use it for internal purposes and
 * possibly even extend it, but it's totally off the limits of the users. Users wishing to
 * programmatically access this functionality should use one of the extensions of this
 * class which is visible to them. These extensions may add additional features like
 * security to this class.
 */
class APIProviderImpl extends AbstractAPIManager implements APIProvider {

    public APIProviderImpl(String username) throws AppManagementException {
        super(username);
    }

    public Set<Provider> getAllProviders() throws AppManagementException {
        Set<Provider> providerSet = new HashSet<Provider>();
        GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                                                                            AppMConstants.PROVIDER_KEY);
        try {
            GenericArtifact[] genericArtifact = artifactManager.getAllGenericArtifacts();
            if (genericArtifact == null || genericArtifact.length == 0) {
                return providerSet;
            }
            for (GenericArtifact artifact : genericArtifact) {
                Provider provider =
                        new Provider(artifact.getAttribute(AppMConstants.PROVIDER_OVERVIEW_NAME));
                provider.setDescription(AppMConstants.PROVIDER_OVERVIEW_DESCRIPTION);
                provider.setEmail(AppMConstants.PROVIDER_OVERVIEW_EMAIL);
                providerSet.add(provider);
            }
        } catch (GovernanceException e) {
            handleException("Failed to get all providers", e);
        }
        return providerSet;
    }

    public Provider getProvider(String providerName) throws AppManagementException {
        Provider provider = null;
        String providerPath = RegistryConstants.GOVERNANCE_REGISTRY_BASE_PATH +
                              AppMConstants.PROVIDERS_PATH + RegistryConstants.PATH_SEPARATOR + providerName;
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                                                                                AppMConstants.PROVIDER_KEY);
            Resource providerResource = registry.get(providerPath);
            String artifactId =
                    providerResource.getUUID();
            if (artifactId == null) {
                throw new AppManagementException("artifact it is null");
            }
            GenericArtifact providerArtifact = artifactManager.getGenericArtifact(artifactId);
            provider = AppManagerUtil.getProvider(providerArtifact);

        } catch (RegistryException e) {
            handleException("Failed to get Provider form : " + providerName, e);
        }
        return provider;
    }

    /**
     * Shows how a given consumer uses the given WebApp.
     *
     * @param apiIdentifier APIIdentifier
     * @param consumerEmail E-mal Address of consumer
     * @return Usage
     */
    public Usage getAPIUsageBySubscriber(APIIdentifier apiIdentifier, String consumerEmail) {
        return null;
    }


    public void addTier(Tier tier) throws AppManagementException {
        addOrUpdateTier(tier, false);
    }

    public void updateTier(Tier tier) throws AppManagementException {
        addOrUpdateTier(tier, true);
    }

    private void addOrUpdateTier(Tier tier, boolean update) throws AppManagementException {
        if (AppMConstants.UNLIMITED_TIER.equals(tier.getName())) {
            throw new AppManagementException("Changes on the '" + AppMConstants.UNLIMITED_TIER + "' " +
                                             "tier are not allowed");
        }

        Set<Tier> tiers = getTiers();
        if (update && !tiers.contains(tier)) {
            throw new AppManagementException("No tier exists by the name: " + tier.getName());
        }

        Set<Tier> finalTiers = new HashSet<Tier>();
        for (Tier tet : tiers) {
            if (!tet.getName().equals(tier.getName())) {
                finalTiers.add(tet);
            }
        }
        finalTiers.add(tier);
        saveTiers(finalTiers);
    }

    private void saveTiers(Collection<Tier> tiers) throws AppManagementException {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMElement root = fac.createOMElement(AppMConstants.POLICY_ELEMENT);
        OMElement assertion = fac.createOMElement(AppMConstants.ASSERTION_ELEMENT);
        try {
            Resource resource = registry.newResource();
            for (Tier tier : tiers) {
                String policy = new String(tier.getPolicyContent());
                assertion.addChild(AXIOMUtil.stringToOM(policy));
                // if (tier.getDescription() != null && !"".equals(tier.getDescription())) {
                //     resource.setProperty(AppMConstants.TIER_DESCRIPTION_PREFIX + tier.getName(),
                //              tier.getDescription());
                //  }
            }
            //resource.setProperty(AppMConstants.TIER_DESCRIPTION_PREFIX + AppMConstants.UNLIMITED_TIER,
            //        AppMConstants.UNLIMITED_TIER_DESC);
            root.addChild(assertion);
            resource.setContent(root.toString());
            registry.put(AppMConstants.API_TIER_LOCATION, resource);
        } catch (XMLStreamException e) {
            handleException("Error while constructing tier policy file", e);
        } catch (RegistryException e) {
            handleException("Error while saving tier configurations to the registry", e);
        }
    }

    public void removeTier(Tier tier) throws AppManagementException {
        if (AppMConstants.UNLIMITED_TIER.equals(tier.getName())) {
            throw new AppManagementException("Changes on the '" + AppMConstants.UNLIMITED_TIER + "' " +
                                             "tier are not allowed");
        }

        Set<Tier> tiers = getTiers();
        if (tiers.remove(tier)) {
            saveTiers(tiers);
        } else {
            throw new AppManagementException("No tier exists by the name: " + tier.getName());
        }
    }

    /**
     * Create a new mobile applcation artifact
     *
     * @param mobileApp Mobile App
     * @throws org.wso2.carbon.appmgt.api.AppManagementException
     */
    public String createMobileApp(MobileApp mobileApp) throws AppManagementException {
        String artifactId = null;
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                    AppMConstants.MOBILE_ASSET_TYPE);
            final String appName = mobileApp.getAppName();

            Map<String, List<String>> attributeListMap = new HashMap<String, List<String>>();
            attributeListMap.put(AppMConstants.API_OVERVIEW_NAME, new ArrayList<String>() {{
                add(appName);
            }});
            GenericArtifact[] existingArtifacts = artifactManager.findGenericArtifacts(attributeListMap);
            if (existingArtifacts != null && existingArtifacts.length > 0) {
                handleResourceAlreadyExistsException("A duplicate mobile application already exists for name : "+
                        mobileApp.getAppName());
            }
            registry.beginTransaction();
            GenericArtifact genericArtifact =
                    artifactManager.newGovernanceArtifact(new QName(mobileApp.getAppName()));
            GenericArtifact artifact = AppManagerUtil.createMobileAppArtifactContent(genericArtifact, mobileApp);
            artifactManager.addGenericArtifact(artifact);
            artifactId = artifact.getId();
            changeLifeCycleStatus(AppMConstants.MOBILE_ASSET_TYPE, artifactId, APPLifecycleActions.CREATE.getStatus());
            String artifactPath = GovernanceUtils.getArtifactPath(registry, artifact.getId());
            Set<String> tagSet = mobileApp.getTags();
            if (tagSet != null) {
                for (String tag : tagSet) {
                    registry.applyTag(artifactPath, tag);
                }
            }

            if(mobileApp.getAppVisibility() != null) {
                AppManagerUtil.setResourcePermissions(mobileApp.getAppProvider(),
                        AppMConstants.API_RESTRICTED_VISIBILITY, mobileApp.getAppVisibility(), artifactPath);
            }
            registry.commitTransaction();
        } catch (RegistryException e) {
            try {
                registry.rollbackTransaction();
            } catch (RegistryException re) {
                handleException(
                        "Error while rolling back the transaction for mobile application: "
                                + mobileApp.getAppName(), re);
            }
            handleException("Error occurred while creating the mobile application : " + mobileApp.getAppName(), e);
        }
        return artifactId;
    }

    /**
     * Create new version of the application
     * @param app applictaion
     * @return app UUID
     * @throws AppManagementException
     */
    @Override
    public String createNewVersion(App app) throws AppManagementException {
        AppRepository appRepository = new DefaultAppRepository(registry);
        String uuid = appRepository.createNewVersion(app);
        return uuid;
    }

    /**
     * Retrieve webapp for the given uuid
     * @param uuid uuid of the Application
     * @return Webapp
     * @throws AppManagementException
     */
    @Override
    public MobileApp getMobileApp(String uuid) throws AppManagementException {
        GenericArtifact artifact = null;
        MobileApp mobileApp = null;

        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, AppMConstants.MOBILE_ASSET_TYPE);
            artifact = artifactManager.getGenericArtifact(uuid);
            if (artifact != null) {
                mobileApp = AppManagerUtil.getMobileApp(artifact);
            }

        } catch (GovernanceException e) {
            handleException("Error occurred while retrieving webapp registry artifact with uuid " + uuid);
        }
        return mobileApp;
    }

    /**
     * Persist WebApp Status into a property of WebApp Registry resource
     *
     * @param artifactId WebApp artifact ID
     * @param apiStatus Current status of the WebApp
     * @throws org.wso2.carbon.appmgt.api.AppManagementException on error
     */
    private void saveAPIStatus(String artifactId, String apiStatus) throws AppManagementException {
        try{
            Resource resource = registry.get(artifactId);
            if (resource != null) {
                String propValue = resource.getProperty(AppMConstants.API_STATUS);
                if (propValue == null) {
                    resource.addProperty(AppMConstants.API_STATUS, apiStatus);
                } else {
                    resource.setProperty(AppMConstants.API_STATUS, apiStatus);
                }
                registry.put(artifactId,resource);
            }
        }catch (RegistryException e) {
            handleException("Error while adding WebApp", e);
        }
    }

    @Override
    public void updateApp(App app) throws AppManagementException {
        AppRepository appRepository = new DefaultAppRepository(registry);
        appRepository.updateApp(app);
    }

    public void updateMobileApp(MobileApp mobileApp) throws AppManagementException {


            try {

                updateMobileAppArtifact(mobileApp, true);

            } catch (AppManagementException e) {
                handleException("Error while updating the WebApp :" +mobileApp.getAppName(),e);
            }


    }


    private void updateMobileAppArtifact(MobileApp mobileApp, boolean updatePermissions) throws
            AppManagementException {


        try {
            registry.beginTransaction();
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                    AppMConstants.MOBILE_ASSET_TYPE);
            GenericArtifact artifact = artifactManager.getGenericArtifact(mobileApp.getAppId());
            if (artifact != null) {

                GenericArtifact updateApiArtifact = AppManagerUtil.createMobileAppArtifactContent(artifact, mobileApp);
                String artifactPath = GovernanceUtils.getArtifactPath(registry, updateApiArtifact.getId());
                artifactManager.updateGenericArtifact(updateApiArtifact);
            }else{
                handleResourceNotFoundException(
                        "Failed to get Mobile App. The artifact corresponding to artifactId " + mobileApp.getAppId() + " does not exist");
            }
//            org.wso2.carbon.registry.core.Tag[] oldTags = registry.getTags(artifactPath);
//            if (oldTags != null) {
//                for (org.wso2.carbon.registry.core.Tag tag : oldTags) {
//                    registry.removeTag(artifactPath, tag.getTagName());
//                }
//            }

//            Set<String> tagSet = api.getTags();
//            if (tagSet != null) {
//                for (String tag : tagSet) {
//                    registry.applyTag(artifactPath, tag);
//                }
//            }




            registry.commitTransaction();
        } catch (Exception e) {
            try {
                registry.rollbackTransaction();
            } catch (RegistryException re) {
                handleException("Error while rolling back the transaction for WebApp: " +mobileApp.getAppName(), re);
            }
            handleException("Error while performing registry transaction operation", e);

        }
    }

    private void checkIfValidTransport(String transport) throws AppManagementException {
        if(!Constants.TRANSPORT_HTTP.equalsIgnoreCase(transport) && !Constants.TRANSPORT_HTTPS.equalsIgnoreCase(transport)){
            handleException("Unsupported Transport [" + transport + "]");
        }
    }

    /**
     * This function is to set resource permissions based on its visibility
     *
     * @param artifactPath WebApp resource path
     * @throws org.wso2.carbon.appmgt.api.AppManagementException Throwing exception
     */
    private void clearResourcePermissions(String artifactPath, APIIdentifier apiId)
            throws AppManagementException {
        try {
            String resourcePath = RegistryUtils.getAbsolutePath(RegistryContext.getBaseInstance(),
                    RegistryConstants.GOVERNANCE_REGISTRY_BASE_PATH
                            + artifactPath);
            String tenantDomain = MultitenantUtils.getTenantDomain(
                    AppManagerUtil.replaceEmailDomainBack(apiId.getProviderName()));
            if (!tenantDomain.equals(org.wso2.carbon.utils.multitenancy.
                    MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                AuthorizationManager authManager = ServiceReferenceHolder.getInstance().
                        getRealmService().getTenantUserRealm(((UserRegistry) registry).getTenantId()).
                        getAuthorizationManager();
                authManager.clearResourceAuthorizations(resourcePath);
            } else {
                RegistryAuthorizationManager authorizationManager = new RegistryAuthorizationManager(ServiceReferenceHolder.getUserRealm());
                authorizationManager.clearResourceAuthorizations(resourcePath);
            }
        } catch (UserStoreException e) {
            handleException("Error while adding role permissions to WebApp", e);
        }
    }

    private String[] getAuthorizedRoles(String artifactPath) throws UserStoreException {
        String  resourcePath = RegistryUtils.getAbsolutePath(RegistryContext.getBaseInstance(),
                                                             RegistryConstants.GOVERNANCE_REGISTRY_BASE_PATH
                                                             + artifactPath);
        RegistryAuthorizationManager authorizationManager = new RegistryAuthorizationManager
                (ServiceReferenceHolder.getUserRealm());
        return authorizationManager.getAllowedRolesForResource(resourcePath,ActionConstants.GET);
    }

    @Override
    public List<App> searchApps(String appType, Map<String, String> searchTerms) throws AppManagementException {


        // If the app type is 'webapp' use the App Repository implementation path.
        if(AppMConstants.WEBAPP_ASSET_TYPE.equalsIgnoreCase(appType)){
            return new DefaultAppRepository(registry).searchApps(appType, searchTerms);
        }else{
            List<App> apps = new ArrayList<App>();
            List<GenericArtifact> appArtifacts = getAppArtifacts(appType);

            for(GenericArtifact artifact : appArtifacts){
                if(isSearchHit(artifact, searchTerms)){
                    apps.add(createApp(artifact, appType));
                }
            }
            return apps;
        }
    }

    public void updateTierPermissions(String tierName, String permissionType, String roles) throws
                                                                                            AppManagementException {
        appMDAO.updateTierPermissions(tierName, permissionType, roles, tenantId);
    }

	@Override
	public Set<TierPermissionDTO> getTierPermissions() throws AppManagementException {
		Set<TierPermissionDTO> tierPermissions = appMDAO.getTierPermissions(tenantId);
		return tierPermissions;
	}

	/**
	 * Get stored custom inSequences from governanceSystem registry
	 *
	 * @throws org.wso2.carbon.appmgt.api.AppManagementException
	 */

	public List<String> getCustomInSequences() throws AppManagementException {

		List<String> sequenceList = new ArrayList<String>();
		try {
			UserRegistry registry = ServiceReferenceHolder.getInstance().getRegistryService()
			                                              .getGovernanceSystemRegistry(tenantId);
			if (registry.resourceExists(AppMConstants.API_CUSTOM_INSEQUENCE_LOCATION)) {
	            org.wso2.carbon.registry.api.Collection inSeqCollection =
	                                                                      (org.wso2.carbon.registry.api.Collection) registry.get(AppMConstants.API_CUSTOM_INSEQUENCE_LOCATION);
	            if (inSeqCollection != null) {
	             //   SequenceMediatorFactory factory = new SequenceMediatorFactory();
	                String[] inSeqChildPaths = inSeqCollection.getChildren();
	                for (int i = 0; i < inSeqChildPaths.length; i++) {
		                Resource inSequence = registry.get(inSeqChildPaths[i]);
		                OMElement seqElment = AppManagerUtil.buildOMElement(inSequence.getContentStream());
		                sequenceList.add(seqElment.getAttributeValue(new QName("name")));
	                }
                }
            }

		} catch (Exception e) {
			handleException("Issue is in getting custom InSequences from the Registry", e);
		}
		return sequenceList;
	}

	/**
	 * Get stored custom outSequences from governanceSystem registry
	 *
	 * @throws org.wso2.carbon.appmgt.api.AppManagementException
	 */

	public List<String> getCustomOutSequences() throws AppManagementException {

		List<String> sequenceList = new ArrayList<String>();
		try {
			UserRegistry registry = ServiceReferenceHolder.getInstance().getRegistryService()
			                                              .getGovernanceSystemRegistry(tenantId);
			if (registry.resourceExists(AppMConstants.API_CUSTOM_OUTSEQUENCE_LOCATION)) {
	            org.wso2.carbon.registry.api.Collection outSeqCollection =
	                                                                       (org.wso2.carbon.registry.api.Collection) registry.get(AppMConstants.API_CUSTOM_OUTSEQUENCE_LOCATION);
	            if (outSeqCollection !=null) {
	                String[] outSeqChildPaths = outSeqCollection.getChildren();
	                for (int i = 0; i < outSeqChildPaths.length; i++) {
		                Resource outSequence = registry.get(outSeqChildPaths[i]);
		                OMElement seqElment = AppManagerUtil.buildOMElement(outSequence.getContentStream());

		                sequenceList.add(seqElment.getAttributeValue(new QName("name")));
	                }
                }
            }

		} catch (Exception e) {
			handleException("Issue is in getting custom OutSequences from the Registry", e);
		}
		return sequenceList;
	}

    /**
     * Change the lifecycle state of a given application
     *
     * @param appType         application type ie: webapp, mobileapp
     * @param appId           application uuid
     * @param lifecycleAction lifecycle action perform on the application
     * @throws AppManagementException
     */
    public void changeLifeCycleStatus(String appType, String appId, String lifecycleAction) throws AppManagementException {

        try {
            String requiredPermission = null;

            if (AppMConstants.LifecycleActions.SUBMIT_FOR_REVIEW.equals(lifecycleAction)) {
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.MOBILE_APP_CREATE;
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.WEB_APP_CREATE;
                }
            } else {
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.MOBILE_APP_PUBLISH;
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    requiredPermission = AppMConstants.Permissions.WEB_APP_PUBLISH;
                }
            }

            if (!AppManagerUtil.checkPermissionQuietly(this.username, requiredPermission)) {
                handleResourceAuthorizationException("The user " + this.username +
                        " is not authorized to perform lifecycle action " + lifecycleAction + " on " +
                        appType + " with uuid " + appId);
            }
            //Check whether the user has enough permissions to change lifecycle
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(this.username);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(this.tenantDomain, true);

            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().
                    getTenantId(this.tenantDomain);

            AuthorizationManager authManager = ServiceReferenceHolder.getInstance().getRealmService().
                    getTenantUserRealm(tenantId).getAuthorizationManager();

            //Get system registry for logged in tenant domain
            Registry systemRegistry = ServiceReferenceHolder.getInstance().
                    getRegistryService().getGovernanceSystemRegistry(tenantId);
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(systemRegistry, appType);
            GenericArtifact appArtifact = artifactManager.getGenericArtifact(appId);
            String resourcePath = RegistryUtils.getAbsolutePath(RegistryContext.getBaseInstance(),
                    RegistryConstants.GOVERNANCE_REGISTRY_BASE_PATH + appArtifact.getPath());

            if (appArtifact != null) {
                if (!authManager.isUserAuthorized(username, resourcePath, "authorize")) {
                    //Throws resource authorization exception
                    handleResourceAuthorizationException("The user " + this.username +
                            " is not authorized to" + appType + " with uuid " + appId);
                }
                //Change lifecycle status
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    appArtifact.invokeAction(lifecycleAction, AppMConstants.MOBILE_LIFE_CYCLE);
                } else if (AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)) {
                    appArtifact.invokeAction(lifecycleAction, AppMConstants.WEBAPP_LIFE_CYCLE);
                }

                //If application is role restricted, deny read rights for Internal/everyone and system/wso2.anonymous.role roles
                if ((AppMConstants.LifecycleActions.PUBLISH.equals(lifecycleAction) ||
                        AppMConstants.LifecycleActions.RE_PUBLISH.equals(lifecycleAction)) &&
                        !StringUtils.isBlank(appArtifact.getAttribute("overview_visibleRoles"))) {

                    authManager.denyRole(AppMConstants.EVERYONE_ROLE, resourcePath, ActionConstants.GET);
                    authManager.denyRole(AppMConstants.ANONYMOUS_ROLE, resourcePath, ActionConstants.GET);
                }

                if (log.isDebugEnabled()) {
                    String logMessage =
                            "Lifecycle action " + lifecycleAction + " has been successfully performed on " + appType
                                    + " with id" + appId;
                    log.debug(logMessage);
                }
            } else {
                handleResourceNotFoundException("Failed to get " + appType + " artifact corresponding to artifactId " +
                        appId + ". Artifact does not exist");
            }
        } catch (UserStoreException e) {
            handleException("Error occurred while performing lifecycle action : " + lifecycleAction + " on " + appType +
                    " with id : " + appId + ". Failed to retrieve tenant id for user : ", e);
        } catch (RegistryException e) {
            handleException("Error occurred while performing lifecycle action : " + lifecycleAction + " on " + appType +
                    " with id : " + appId, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Get the available next lifecycle actions of a given application
     *
     * @param appId   application type
     * @param appType application type
     * @return
     */
    public String[] getAllowedLifecycleActions(String appId, String appType) throws AppManagementException {

        String[] actions = null;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(this.username);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(this.tenantDomain, true);

            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, appType);
            GenericArtifact appArtifact = artifactManager.getGenericArtifact(appId);
            if (appArtifact != null) {
                if (AppMConstants.MOBILE_ASSET_TYPE.equals(appType)) {
                    //Get all the actions corresponding to current state of the api artifact
                    actions = appArtifact.getAllLifecycleActions(AppMConstants.MOBILE_LIFE_CYCLE);
                }else if(AppMConstants.WEBAPP_ASSET_TYPE.equals(appType)){
                    actions = appArtifact.getAllLifecycleActions(AppMConstants.WEBAPP_LIFE_CYCLE);
                } else {
                    handleException("Unsupported application type : " + appType +" provided");
                }
            } else {
                handleResourceNotFoundException("Failed to get " + appType + " artifact corresponding to artifactId " +
                        appId + ". Artifact does not exist");
            }
        } catch (GovernanceException e) {
            handleException("Error occurred while retrieving allowed lifecycle actions to perform on " + appType +
                    " with id : " + appId, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return actions;
    }

    public boolean subscribeMobileApp(String userId, String appId) throws AppManagementException {

        String path = "users/" + userId + "/subscriptions/mobileapp/" + appId;
        Resource resource = null;
        boolean isSubscribed = false;
        try {
            UserRegistry sysRegistry = ServiceReferenceHolder.getInstance().getRegistryService()
                    .getGovernanceSystemRegistry(tenantId);
            if (!sysRegistry.resourceExists(path)) {
                resource = sysRegistry.newResource();
                resource.setContent("");
                sysRegistry.put(path, resource);
                isSubscribed = true;
            }
        } catch (org.wso2.carbon.registry.api.RegistryException e) {
            handleException("Error occurred while adding subscription registry resource for mobileapp with id :" +
                    appId, e);
        }
        return isSubscribed;
    }


    public boolean unSubscribeMobileApp(String userId, String appId) throws AppManagementException {
        String path = "users/" + userId + "/subscriptions/mobileapp/" + appId;
        boolean isUnSubscribed = false;
        try {
            if (registry.resourceExists(path)) {
                registry.delete(path);
                isUnSubscribed = true;
            }
        } catch (org.wso2.carbon.registry.api.RegistryException e) {
            handleException("Error occurred while removing subscription registry resource for mobileapp with id :" +
                    appId, e);
        }
        return isUnSubscribed;
    }

    /**
     *
     * Returns the 'app' (e.g. webapp, mobileapp) registry artifacts.
     *
     * @param appType
     * @return
     * @throws AppManagementException
     */
    private List<GenericArtifact> getAppArtifacts(String appType) throws AppManagementException {

        List<GenericArtifact> appArtifacts = new ArrayList<GenericArtifact>();

        boolean isTenantFlowStarted = false;
        try {
            if (tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                isTenantFlowStarted = true;
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            }
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry, appType);
            GenericArtifact[] artifacts = artifactManager.getAllGenericArtifacts();
            for (GenericArtifact artifact : artifacts) {
                appArtifacts.add(artifact);
            }

        } catch (RegistryException e) {
            handleException("Failed to get APIs from the registry", e);
        } finally {
            if (isTenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        return appArtifacts;
    }


    private App createApp(GenericArtifact artifact, String appType) throws AppManagementException {
        AppFactory appFactory = null;
        if(AppMConstants.MOBILE_ASSET_TYPE.equals(appType)){
            appFactory = new MobileAppFactory();
        }

        return appFactory.createApp(artifact, registry);
    }

    private boolean isSearchHit(GenericArtifact artifact, Map<String, String> searchTerms) throws AppManagementException {

        boolean isSearchHit = true;

        for(Map.Entry<String, String> term : searchTerms.entrySet()){
            try {
                if("ID".equalsIgnoreCase(term.getKey())) {
                    if(!artifact.getId().equals(term.getValue())){
                        isSearchHit = false;
                        break;
                    }
                }else if(!term.getValue().equals(artifact.getAttribute(getRxtAttributeName(term.getKey())))){
                    isSearchHit = false;
                    break;
                }
            } catch (GovernanceException e) {
                String errorMessage = String.format("Error while determining whether artifact '%s' is a search hit.", artifact.getId());
                throw new AppManagementException(errorMessage, e);
            }
        }

        return isSearchHit;
    }

    private String getRxtAttributeName(String searchKey) {

        String rxtAttributeName = null;

        if(searchKey.equalsIgnoreCase("NAME")){
            rxtAttributeName = AppMConstants.API_OVERVIEW_NAME;
        }else if(searchKey.equalsIgnoreCase("PROVIDER")){
            rxtAttributeName = AppMConstants.API_OVERVIEW_PROVIDER;
        }else if(searchKey.equalsIgnoreCase("VERSION")){
            rxtAttributeName = AppMConstants.API_OVERVIEW_VERSION;
        }

        return rxtAttributeName;
    }

    public String addResourceFile(String resourcePath, FileContent resourceFile) throws AppManagementException {
        try {
            Resource thumb = registry.newResource();
            thumb.setContentStream(resourceFile.getContent());
            thumb.setMediaType(resourceFile.getContentType());
            registry.put(resourcePath, thumb);
            if(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)){
                return RegistryConstants.PATH_SEPARATOR + "registry"
                        + RegistryConstants.PATH_SEPARATOR + "resource"
                        + RegistryConstants.PATH_SEPARATOR + "_system"
                        + RegistryConstants.PATH_SEPARATOR + "governance"
                        + resourcePath;
            }
            else{
                return "/t/"+tenantDomain+ RegistryConstants.PATH_SEPARATOR + "registry"
                        + RegistryConstants.PATH_SEPARATOR + "resource"
                        + RegistryConstants.PATH_SEPARATOR + "_system"
                        + RegistryConstants.PATH_SEPARATOR + "governance"
                        + resourcePath;
            }
        } catch (RegistryException e) {
            handleException("Error while adding the resource to the registry", e);
        }
        return null;
    }

    /**
     * Remove mobile applications binary files from storage
     * @param filePath file path of the banner image, thumbnail, screenshots and app binary
     * @throws AppManagementException
     */
    public void removeBinaryFromStorage(String filePath) throws AppManagementException {
        if (StringUtils.isEmpty(filePath)) {
            handleException("Mobile Application BinaryFileStorage Configuration cannot be found." +
                    " Pleas check the configuration in app-management.xml ");
        }

        File binaryFile = new File(filePath);
        if (!binaryFile.exists()) {
            handleException("Binary file " + filePath + " does not exist");
        }

        boolean isDeleted = binaryFile.delete();
        if (!isDeleted) {
            handleException("Error occurred while deleting file " + filePath);
        }
    }

    /**
     * Generate one-time download link content in Database
     * @param appId mobile application id that the one-time download link generated for
     * @return UUID of the download link
     * @throws AppManagementException
     */
    public String generateOneTimeDownloadLink(String appId) throws AppManagementException {

        String downloadLinkUUID = null;
        try {
            GenericArtifactManager artifactManager = AppManagerUtil.getArtifactManager(registry,
                    AppMConstants.MOBILE_ASSET_TYPE);
            GenericArtifact mobileAppArtifact = artifactManager.getGenericArtifact(appId);
            if (mobileAppArtifact == null) {
                handleResourceNotFoundException(
                        "Failed to generate one-time download link for Mobile App. The artifact corresponding to artifactId "
                                + appId + " does not exist");
            }

            if (!AppMConstants.MOBILE_APP_TYPE_PUBLIC.equals(mobileAppArtifact.getAttribute(AppMConstants.MOBILE_APP_OVERVIEW_TYPE))) {
                OneTimeDownloadLink oneTimeDownloadLink = new OneTimeDownloadLink();
                UUID contentUUID = UUID.randomUUID();
                downloadLinkUUID = contentUUID.toString();
                oneTimeDownloadLink.setUUID(downloadLinkUUID);
                oneTimeDownloadLink.setFileName(mobileAppArtifact.getAttribute(AppMConstants.MOBILE_APP_OVERVIEW_URL));
                oneTimeDownloadLink.setDownloaded(false);
                appRepository.persistOneTimeDownloadLink(oneTimeDownloadLink);
            }
        } catch (RegistryException e) {
            handleException("Error occurred while generating one-time download link for mobile application : " + appId, e);
        }
        return downloadLinkUUID;
    }


    /**
     * Retrieve one-time download link details from database
     * @param UUID UUID of the one-time download link
     * @return
     * @throws AppManagementException
     */
    public OneTimeDownloadLink getOneTimeDownloadLinkDetails(String UUID) throws AppManagementException{
        return appRepository.getOneTimeDownloadLinkDetails(UUID);
    }

    /**
     * Update one-time download link details in database
     * @param oneTimeDownloadLink OneTimeDownloadLink content
     * @throws AppManagementException
     */
    public void updateOneTimeDownloadLinkStatus(OneTimeDownloadLink oneTimeDownloadLink) throws AppManagementException{
        appRepository.updateOneTimeDownloadLinkStatus(oneTimeDownloadLink);
    }

    public String getGatewayEndpoint() {
        Environment gatewayEnvironment = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                getAPIManagerConfiguration().getApiGatewayEnvironments().get(0);

        String gatewayUrl = gatewayEnvironment.getApiGatewayEndpoint().split(",")[0];
        return gatewayUrl;
    }

    public String uploadImage(FileContent fileContent) throws AppManagementException {
        UUID contentUUID = UUID.randomUUID();
        String fileExtension = FilenameUtils.getExtension(fileContent.getFileName());
        String filename = generateBinaryUUID() + "." + fileExtension;
        fileContent.setFileName(filename);
        fileContent.setContentType("image/" + fileExtension);
        fileContent.setUuid(contentUUID.toString());
        try {
            fileContent.setContentLength(fileContent.getContent().available());
        } catch (IOException e) {
            handleException("Error occurred while uploading static content", e);
        }
        appRepository.persistStaticContents(fileContent);
        return contentUUID.toString() + File.separator + fileContent.getFileName();
    }

    private static String generateBinaryUUID() {
        SecureRandom secRandom = new SecureRandom();
        byte[] result = new byte[8];
        secRandom.nextBytes(result);
        String uuid = String.valueOf(Hex.encodeHex(result));
        return uuid;
    }
}