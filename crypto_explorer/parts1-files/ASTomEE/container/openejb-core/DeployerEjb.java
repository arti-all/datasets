/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.openejb.assembler;

import org.apache.openejb.ClassLoaderUtil;
import org.apache.openejb.NoSuchApplicationException;
import org.apache.openejb.OpenEJBException;
import org.apache.openejb.OpenEJBRuntimeException;
import org.apache.openejb.UndeployException;
import org.apache.openejb.assembler.classic.AppInfo;
import org.apache.openejb.assembler.classic.Assembler;
import org.apache.openejb.config.AppModule;
import org.apache.openejb.config.ConfigurationFactory;
import org.apache.openejb.config.DeploymentLoader;
import org.apache.openejb.config.DeploymentModule;
import org.apache.openejb.config.WebModule;
import org.apache.openejb.config.sys.AdditionalDeployments;
import org.apache.openejb.config.sys.Deployments;
import org.apache.openejb.config.sys.JaxbOpenejb;
import org.apache.openejb.loader.Files;
import org.apache.openejb.loader.IO;
import org.apache.openejb.loader.ProvisioningUtil;
import org.apache.openejb.loader.SystemInstance;
import org.apache.openejb.util.LogCategory;
import org.apache.openejb.util.Logger;

import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.enterprise.inject.Alternative;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import static javax.ejb.TransactionManagementType.BEAN;
import static org.apache.openejb.config.ConfigurationFactory.ADDITIONAL_DEPLOYMENTS;
import static org.apache.openejb.loader.ProvisioningUtil.realLocation;

@SuppressWarnings("EjbProhibitedPackageUsageInspection")
@Stateless(name = "openejb/Deployer")
@Remote(Deployer.class)
@TransactionManagement(BEAN)
@Alternative
public class DeployerEjb implements Deployer {
    private static final Logger LOGGER = Logger.getInstance(LogCategory.OPENEJB, DeployerEjb.class);

    public static final String OPENEJB_DEPLOYER_FORCED_APP_ID_PROP = "openejb.deployer.forced.appId";

    public static final String OPENEJB_USE_BINARIES = "openejb.deployer.binaries.use";
    public static final String OPENEJB_PATH_BINARIES = "openejb.deployer.binaries.path";
    public static final String OPENEJB_VALUE_BINARIES = "openejb.deployer.binaries.value";

    public static final ThreadLocal<Boolean> AUTO_DEPLOY = new ThreadLocal<Boolean>();

    private final static File uniqueFile;
    private final static boolean oldWarDeployer = "old".equalsIgnoreCase(SystemInstance.get().getOptions().get("openejb.deployer.war", "new"));
    private final static String OPENEJB_DEPLOYER_SAVE_DEPLOYMENTS = "openejb.deployer.save-deployments";
    private final static boolean SAVE_DEPLOYMENTS = SystemInstance.get().getOptions().get(OPENEJB_DEPLOYER_SAVE_DEPLOYMENTS, false);

    static {
        final String uniqueName = "OpenEJB-" + new BigInteger(128, new SecureRandom()).toString(Character.MAX_RADIX);
        final String tempDir = System.getProperty("java.io.tmpdir");
        File unique;
        try {
            unique = new File(tempDir, uniqueName).getCanonicalFile();
            if (!unique.createNewFile()) {
                throw new IOException("Failed to create file in temp: " + unique);
            }
        } catch (IOException e) {
            // same trying in work directory
            unique = new File(SystemInstance.get().getBase().getDirectory(), "work");
            if (unique.exists()) {
                try {
                    unique = new File(unique, uniqueName).getCanonicalFile();
                    if (!unique.createNewFile()) {
                        throw new IOException("Failed to create file in work: " + unique);
                    }
                } catch (IOException e1) {
                    throw new OpenEJBRuntimeException(e);
                }
            } else {
                throw new OpenEJBRuntimeException("can't create unique file, please set java.io.tmpdir to a writable folder or create work folder", e);
            }
        }
        uniqueFile = unique;
        uniqueFile.deleteOnExit();
    }

    private final DeploymentLoader deploymentLoader;
    private final ConfigurationFactory configurationFactory;
    private final Assembler assembler;

    public DeployerEjb() {
        deploymentLoader = new DeploymentLoader();
        configurationFactory = new ConfigurationFactory();
        assembler = (Assembler) SystemInstance.get().getComponent(org.apache.openejb.spi.Assembler.class);
    }

    @Override
    public String getUniqueFile() {
        return uniqueFile.getAbsolutePath();
    }

    @Override
    public Collection<AppInfo> getDeployedApps() {
        return assembler.getDeployedApplications();
    }

    @Override
    public AppInfo deploy(final String location) throws OpenEJBException {
        return deploy(location, null);
    }

    @Override
    public AppInfo deploy(final Properties properties) throws OpenEJBException {
        return deploy(null, properties);
    }

    @Override
    public AppInfo deploy(final String inLocation, Properties properties) throws OpenEJBException {
        String rawLocation = inLocation;
        if (rawLocation == null && properties == null) {
            throw new NullPointerException("location and properties are null");
        }
        if (rawLocation == null) {
            rawLocation = properties.getProperty(FILENAME);
        }
        if (properties == null) {
            properties = new Properties();
        }

        AppModule appModule = null;

        final File file;
        if ("true".equalsIgnoreCase(properties.getProperty(OPENEJB_USE_BINARIES, "false"))) {
            file = copyBinaries(properties);
        } else {
            file = new File(realLocation(rawLocation));
        }

        final boolean autoDeploy = Boolean.parseBoolean(properties.getProperty("openejb.app.autodeploy", "false"));

        if (WebAppDeployer.Helper.isWebApp(file) && !oldWarDeployer) {
            AUTO_DEPLOY.set(autoDeploy);
            try {
                return SystemInstance.get().getComponent(WebAppDeployer.class)
                                     .deploy(contextRoot(properties, file.getAbsolutePath()), file);
            } finally {
                AUTO_DEPLOY.remove();
            }
        }

        AppInfo appInfo = null;

        try {
            appModule = deploymentLoader.load(file);

            // Add any alternate deployment descriptors to the modules
            final Map<String, DeploymentModule> modules = new TreeMap<String, DeploymentModule>();
            for (final DeploymentModule module : appModule.getEjbModules()) {
                modules.put(module.getModuleId(), module);
            }
            for (final DeploymentModule module : appModule.getClientModules()) {
                modules.put(module.getModuleId(), module);
            }
            for (final WebModule module : appModule.getWebModules()) {
                final String contextRoot = contextRoot(properties, module.getJarLocation());
                if (contextRoot != null) {
                    module.setContextRoot(contextRoot);
                }
                modules.put(module.getModuleId(), module);
            }
            for (final DeploymentModule module : appModule.getConnectorModules()) {
                modules.put(module.getModuleId(), module);
            }

            for (final Map.Entry<Object, Object> entry : properties.entrySet()) {
                String name = (String) entry.getKey();
                if (name.startsWith(ALT_DD + "/")) {
                    name = name.substring(ALT_DD.length() + 1);

                    final DeploymentModule module;
                    final int slash = name.indexOf('/');
                    if (slash > 0) {
                        final String moduleId = name.substring(0, slash);
                        name = name.substring(slash + 1);
                        module = modules.get(moduleId);
                    } else {
                        module = appModule;
                    }

                    if (module != null) {
                        final String value = (String) entry.getValue();
                        final File dd = new File(value);
                        if (dd.canRead()) {
                            module.getAltDDs().put(name, dd.toURI().toURL());
                        } else {
                            module.getAltDDs().put(name, value);
                        }
                    }
                }
            }

            appInfo = configurationFactory.configureApplication(appModule);
            appInfo.autoDeploy = autoDeploy;

            if (properties != null && properties.containsKey(OPENEJB_DEPLOYER_FORCED_APP_ID_PROP)) {
                appInfo.appId = properties.getProperty(OPENEJB_DEPLOYER_FORCED_APP_ID_PROP);
            }

            assembler.createApplication(appInfo);

            if (SAVE_DEPLOYMENTS || "true".equalsIgnoreCase(properties.getProperty(OPENEJB_DEPLOYER_SAVE_DEPLOYMENTS, "false"))) {
                saveDeployment(file, true);
            }

            return appInfo;

        } catch (Throwable e) {
            // destroy the class loader for the failed application
            if (appModule != null) {
                ClassLoaderUtil.destroyClassLoader(appModule.getJarLocation());
            }

            if (null != appInfo) {
                ClassLoaderUtil.destroyClassLoader(appInfo.appId, appInfo.path);
            }

            LOGGER.error("Can't deploy " + inLocation, e);

            if (e instanceof javax.validation.ValidationException) {
                throw (javax.validation.ValidationException) e;
            }

            if (e instanceof OpenEJBException) {
                if (e.getCause() instanceof javax.validation.ValidationException) {
                    throw (javax.validation.ValidationException) e.getCause();
                }
                throw (OpenEJBException) e;
            }
            throw new OpenEJBException(e);
        }
    }

    private static File copyBinaries(final Properties props) throws OpenEJBException {
        final File dump = ProvisioningUtil.cacheFile(props.getProperty(OPENEJB_PATH_BINARIES, "dump.war"));
        if (dump.exists()) {
            Files.delete(dump);
            final String name = dump.getName();
            if (name.endsWith("ar") && name.length() > 4) {
                final File exploded = new File(dump.getParentFile(), name.substring(0, name.length() - 4));
                if (exploded.exists()) {
                    Files.delete(exploded);
                }
            }
        }
        try {
            IO.copy(byte[].class.cast(props.get(OPENEJB_VALUE_BINARIES)), dump);
        } catch (final IOException e) {
            throw new OpenEJBException(e);
        }
        return dump;
    }

    private synchronized void saveDeployment(final File file, final boolean add) {
        final Deployments deps = new Deployments();
        if (file.isDirectory()) {
            deps.setDir(file.getAbsolutePath());
        } else {
            deps.setFile(file.getAbsolutePath());
        }

        File config;
        try {
            config = SystemInstance.get().getBase().getFile(ADDITIONAL_DEPLOYMENTS, false);
        } catch (IOException e) {
            config = null;
        }
        if (config == null || !config.getParentFile().exists()) {
            LOGGER.info("can't save the added app because the conf folder doesn't exist, it will not be present next time you'll start");
            return;
        }

        // dump it
        OutputStream os = null;
        try {
            final AdditionalDeployments additionalDeployments;
            if (config.exists() && config.length() > 0) {
                final InputStream fis = IO.read(config);
                try {
                    additionalDeployments = JaxbOpenejb.unmarshal(AdditionalDeployments.class, fis);
                } finally {
                    IO.close(fis);
                }
            } else {
                additionalDeployments = new AdditionalDeployments();
            }

            if (add) {
                if (!additionalDeployments.getDeployments().contains(deps)) {
                    additionalDeployments.getDeployments().add(deps);
                }
            } else {
                final Iterator<Deployments> it = additionalDeployments.getDeployments().iterator();
                while (it.hasNext()) {
                    final Deployments current = it.next();
                    if (deps.getDir() != null && deps.getDir().equals(current.getDir())) {
                        it.remove();
                        break;
                    } else if (deps.getFile() != null && deps.getFile().equals(current.getFile())) {
                        it.remove();
                        break;
                    } else { // exploded dirs
                        final String jar = deps.getFile();
                        if (jar != null && jar.length() > 3 && jar.substring(0, jar.length() - 4).equals(deps.getDir())) {
                            it.remove();
                            break;
                        }
                    }
                }
            }
            os = IO.write(config);
            JaxbOpenejb.marshal(AdditionalDeployments.class, additionalDeployments, os);
        } catch (Exception e) {
            LOGGER.error("can't save the added app, will not be present next time you'll start", e);
        } finally {
            IO.close(os);
        }
    }

    @Override
    public void undeploy(final String moduleId) throws UndeployException, NoSuchApplicationException {
        try {
            assembler.destroyApplication(moduleId);
        } catch (NoSuchApplicationException nsae) {
            try {
                assembler.destroyApplication(realLocation(moduleId));
            } catch (Exception e) {
                try {
                    assembler.destroyApplication(new File(moduleId).getAbsolutePath());
                } catch (Exception e2) {
                    try {
                        assembler.destroyApplication(new File(realLocation(moduleId)).getAbsolutePath());
                    } catch (Exception e3) {
                        throw nsae;
                    }
                }
            }
        }
        saveDeployment(new File(moduleId), false);
    }

    private String contextRoot(final Properties properties, final String jarPath) {
        return properties.getProperty("webapp." + jarPath + ".context-root");
    }

    @Override
    public void reload(final String moduleId) {
        for (final AppInfo info : assembler.getDeployedApplications()) {
            if (info.path.equals(moduleId)) {
                reload(info);
                break;
            }
        }
    }

    private void reload(final AppInfo info) {
        if (info.webAppAlone) {
            SystemInstance.get().getComponent(WebAppDeployer.class).reload(info.path);
        } else {
            try {
                assembler.destroyApplication(info);
                assembler.createApplication(info);
            } catch (Exception e) {
                throw new OpenEJBRuntimeException(e);
            }
        }
    }
}
