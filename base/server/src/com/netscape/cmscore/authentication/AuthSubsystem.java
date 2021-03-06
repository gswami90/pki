// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.authentication;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthManagerProxy;
import org.dogtagpki.server.authentication.AuthManagersConfig;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authentication.IAuthManager;

import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EAuthMgrNotFound;
import com.netscape.certsrv.authentication.EAuthMgrPluginNotFound;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cms.authentication.CMCAuth;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * Default authentication subsystem
 * <P>
 *
 * @author cfu
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class AuthSubsystem implements ISubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthSubsystem.class);

    public final static String ID = "auths";

    public final static String PROP_CLASS = "class";
    public final static String PROP_IMPL = "impl";
    public final static String PROP_PLUGIN = "pluginName";

    /**
     * Constant for password based authentication plugin ID.
     */
    public final static String PASSWDUSERDB_PLUGIN_ID = "passwdUserDBAuthPlugin";

    /**
     * Constant for certificate based authentication plugin ID.
     */
    public final static String CERTUSERDB_PLUGIN_ID = "certUserDBAuthPlugin";

    /**
     * Constant for challenge based authentication plugin ID.
     */
    public final static String CHALLENGE_PLUGIN_ID = "challengeAuthPlugin";

    /**
     * Constant for null authentication plugin ID.
     */
    public final static String NULL_PLUGIN_ID = "nullAuthPlugin";

    /**
     * Constant for ssl client authentication plugin ID.
     */
    public final static String SSLCLIENTCERT_PLUGIN_ID = "sslClientCertAuthPlugin";

    /**
     * Constant for password based authentication manager ID.
     */
    public final static String PASSWDUSERDB_AUTHMGR_ID = "passwdUserDBAuthMgr";

    /**
     * Constant for certificate based authentication manager ID.
     */
    public final static String CERTUSERDB_AUTHMGR_ID = "certUserDBAuthMgr";

    /**
     * Constant for challenge based authentication manager ID.
     */
    public final static String CHALLENGE_AUTHMGR_ID = "challengeAuthMgr";

    /**
     * Constant for null authentication manager ID.
     */
    public final static String NULL_AUTHMGR_ID = "nullAuthMgr";

    /**
     * Constant for ssl client authentication manager ID.
     */
    public final static String SSLCLIENTCERT_AUTHMGR_ID = "sslClientCertAuthMgr";

    /**
     * Constant for CMC authentication plugin ID.
     */
    public final static String CMCAUTH_PLUGIN_ID = "CMCAuth";

    /**
     * Constant for CMC authentication manager ID.
     */
    public final static String CMCAUTH_AUTHMGR_ID = "CMCAuth";

    /**
     * Constant for CMC user-signed authentication manager ID.
     */
    public final static String CMC_USER_SIGNED_AUTH_AUTHMGR_ID = "CMCUserSignedAuth";

    public Hashtable<String, AuthMgrPlugin> mAuthMgrPlugins = new Hashtable<String, AuthMgrPlugin>();
    public Hashtable<String, AuthManagerProxy> mAuthMgrInsts = new Hashtable<String, AuthManagerProxy>();
    private String mId = "auths";
    private AuthenticationConfig mConfig;

    // singleton enforcement

    private static AuthSubsystem mInstance = new AuthSubsystem();

    public static synchronized AuthSubsystem getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    private AuthSubsystem() {
    }

    /**
     * Initializes the authentication subsystem from the config store.
     * Load Authentication manager plugins, create and initialize
     * initialize authentication manager instances.
     * @param config The configuration store.
     */
    public void init(IConfigStore config)
            throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();

        try {
            mConfig = engineConfig.getAuthenticationConfig();

            // hardcode admin and agent plugins required for the server to be
            // functional.

            AuthMgrPlugin newPlugin = null;

            newPlugin = new AuthMgrPlugin(PASSWDUSERDB_PLUGIN_ID,
                    PasswdUserDBAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(PASSWDUSERDB_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(CERTUSERDB_PLUGIN_ID,
                    CertUserDBAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(CERTUSERDB_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(CHALLENGE_PLUGIN_ID,
                    ChallengePhraseAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(CHALLENGE_PLUGIN_ID, newPlugin);

            // Bugscape #56659
            //   Removed NullAuthMgr to harden CMS. Otherwise,
            //   any request submitted for nullAuthMgr will
            //   be approved automatically
            //
            // newPlugin = new AuthMgrPlugin(NULL_PLUGIN_ID,
            //            NullAuthentication.class.getName());
            // newPlugin.setVisible(false);
            // mAuthMgrPlugins.put(NULL_PLUGIN_ID, newPlugin);

            newPlugin = new AuthMgrPlugin(SSLCLIENTCERT_PLUGIN_ID,
                    SSLClientCertAuthentication.class.getName());
            newPlugin.setVisible(false);
            mAuthMgrPlugins.put(SSLCLIENTCERT_PLUGIN_ID, newPlugin);

            // get auth manager plugins.

            IConfigStore c = mConfig.getSubStore(PROP_IMPL);
            Enumeration<String> mImpls = c.getSubStoreNames();

            while (mImpls.hasMoreElements()) {
                String id = mImpls.nextElement();
                String pluginPath = c.getString(id + "." + PROP_CLASS);

                AuthMgrPlugin plugin = new AuthMgrPlugin(id, pluginPath);

                mAuthMgrPlugins.put(id, plugin);
            }

            logger.debug("loaded auth plugins");

            // hardcode admin and agent auth manager instances for the server
            // to be functional

            PasswdUserDBAuthentication passwdUserDBAuth = new PasswdUserDBAuthentication();
            passwdUserDBAuth.setAuthenticationConfig(mConfig);
            passwdUserDBAuth.init(PASSWDUSERDB_AUTHMGR_ID, PASSWDUSERDB_PLUGIN_ID, null);
            mAuthMgrInsts.put(PASSWDUSERDB_AUTHMGR_ID, new
                    AuthManagerProxy(true, passwdUserDBAuth));

            logger.debug("loaded password based auth manager");

            CertUserDBAuthentication certUserDBAuth = new CertUserDBAuthentication();
            certUserDBAuth.setAuthenticationConfig(mConfig);
            certUserDBAuth.init(CERTUSERDB_AUTHMGR_ID, CERTUSERDB_PLUGIN_ID, null);
            mAuthMgrInsts.put(CERTUSERDB_AUTHMGR_ID, new AuthManagerProxy(true, certUserDBAuth));

            logger.debug("loaded certificate based auth manager");

            ChallengePhraseAuthentication challengeAuth = new ChallengePhraseAuthentication();
            challengeAuth.setAuthenticationConfig(mConfig);
            challengeAuth.init(CHALLENGE_AUTHMGR_ID, CHALLENGE_PLUGIN_ID, null);
            mAuthMgrInsts.put(CHALLENGE_AUTHMGR_ID, new AuthManagerProxy(true, challengeAuth));

            logger.debug("loaded challenge phrase auth manager");

            CMCAuth cmcAuth = new CMCAuth();
            cmcAuth.setAuthenticationConfig(mConfig);
            cmcAuth.init(CMCAUTH_AUTHMGR_ID, CMCAUTH_PLUGIN_ID, null);
            mAuthMgrInsts.put(CMCAUTH_AUTHMGR_ID, new AuthManagerProxy(true, cmcAuth));

            logger.debug("loaded cmc auth manager");

            // #56659
            // NullAuthentication nullAuth = new NullAuthentication();
            // nullAuth.setAuthenticationConfig(mConfig);
            // nullAuth.init(NULL_AUTHMGR_ID, NULL_PLUGIN_ID, null);
            // mAuthMgrInsts.put(NULL_AUTHMGR_ID, new AuthManagerProxy(true, nullAuth));
            //
            // logger.debug("loaded null auth manager");

            SSLClientCertAuthentication sslClientCertAuth = new SSLClientCertAuthentication();
            sslClientCertAuth.setAuthenticationConfig(mConfig);
            sslClientCertAuth.init(SSLCLIENTCERT_AUTHMGR_ID, SSLCLIENTCERT_PLUGIN_ID, null);
            mAuthMgrInsts.put(SSLCLIENTCERT_AUTHMGR_ID, new AuthManagerProxy(true, sslClientCertAuth));

            logger.debug("loaded sslClientCert auth manager");

            // get auth manager instances.
            AuthManagersConfig instancesConfig = mConfig.getAuthManagersConfig();
            Enumeration<String> instances = instancesConfig.getSubStoreNames();

            while (instances.hasMoreElements()) {
                String insName = instances.nextElement();
                logger.debug("AuthSubsystem: initializing authentication manager " + insName);

                AuthManagerConfig authMgrConfig = instancesConfig.getAuthManagerConfig(insName);
                String implName = authMgrConfig.getString(PROP_PLUGIN);
                AuthMgrPlugin plugin =
                        mAuthMgrPlugins.get(implName);

                if (plugin == null) {
                    logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_CANT_FIND_PLUGIN", implName));
                    throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND",
                            implName));
                }
                String className = plugin.getClassPath();

                boolean isEnable = false;
                // Instantiate and init the authentication manager.
                IAuthManager authMgrInst = null;

                try {
                    authMgrInst = (IAuthManager)
                            Class.forName(className).newInstance();

                    authMgrInst.init(insName, implName, authMgrConfig);
                    isEnable = true;

                    logger.info("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_ADD_AUTH_INSTANCE", insName));

                } catch (ClassNotFoundException e) {
                    logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

                } catch (IllegalAccessException e) {
                    logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

                } catch (InstantiationException e) {
                    logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_AUTHSUB_ERROR", e.toString()));
                    throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

                } catch (EBaseException e) {
                    String message = CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", insName, e.toString());
                    logger.warn("AuthSubsystem: " + message, e);
                    // Skip the authenticaiton instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console

                } catch (Throwable e) {
                    String message = CMS.getLogMessage("CMSCORE_AUTH_AUTH_INIT_ERROR", insName, e.toString());
                    logger.warn("AuthSubsystem: " + message, e);
                    // Skip the authenticaiton instance if
                    // it is mis-configurated. This give
                    // administrator another chance to
                    // fix the problem via console
                }
                // add manager instance to list.
                mAuthMgrInsts.put(insName, new
                        AuthManagerProxy(isEnable, authMgrInst));

                logger.debug("loaded auth instance " + insName + " impl " + implName);
            }
            logger.info("AuthSubsystem: " + CMS.getLogMessage("INIT_DONE", getId()));

        } catch (EBaseException e) {
            logger.error("Unable to initialize AuthSubsystem: " + e.getMessage(), e);
            if (engine.isPreOpMode()) {
                logger.warn("AuthSubsystem.init(): Swallow exception in pre-op mode");
                return;
            }
            throw e;
        }
    }

    /**
     * Authenticate to the named authentication manager instance
     * <p>
     *
     * @param authCred authentication credentials subject to the
     *            requirements of each authentication manager
     * @param authMgrName name of the authentication manager instance
     * @return authentication token with individualized authenticated
     *         information.
     * @exception EMissingCredential If a required credential for the
     *                authentication manager is missing.
     * @exception EInvalidCredentials If the credentials cannot be authenticated
     * @exception EAuthMgrNotFound The auth manager is not found.
     * @exception EBaseException If an internal error occurred.
     */
    public IAuthToken authenticate(
            IAuthCredentials authCred, String authMgrInstName)
            throws EMissingCredential, EInvalidCredentials,
            EAuthMgrNotFound, EBaseException {
        AuthManagerProxy proxy = mAuthMgrInsts.get(authMgrInstName);

        if (proxy == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        if (!proxy.isEnable()) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        IAuthManager authMgrInst = proxy.getAuthManager();

        if (authMgrInst == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        return (authMgrInst.authenticate(authCred));
    }

    /**
     * Gets a list of required authentication credential names
     * of the specified authentication manager.
     *
     * @param authMgrName The authentication manager name
     * @return a Vector of required credential attribute names.
     */
    public String[] getRequiredCreds(String authMgrInstName)
            throws EAuthMgrNotFound {
        IAuthManager authMgrInst = get(authMgrInstName);

        if (authMgrInst == null) {
            throw new EAuthMgrNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", authMgrInstName));
        }
        return authMgrInst.getRequiredCreds();
    }

    /**
     * Gets configuration parameters for the given
     * authentication manager plugin.
     *
     * @param implName Name of the authentication plugin.
     * @return Hashtable of required parameters.
     */
    public String[] getConfigParams(String implName)
            throws EAuthMgrPluginNotFound, EBaseException {
        // is this a registered implname?
        AuthMgrPlugin plugin = mAuthMgrPlugins.get(implName);

        if (plugin == null) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_PLUGIN_NOT_FOUND", implName));
            throw new EAuthMgrPluginNotFound(CMS.getUserMessage("CMS_AUTHENTICATION_AUTHMGR_NOT_FOUND", implName));
        }

        // a temporary instance
        IAuthManager authMgrInst = null;
        String className = plugin.getClassPath();

        try {
            authMgrInst = (IAuthManager)
                    Class.forName(className).newInstance();
            return (authMgrInst.getConfigParams());

        } catch (InstantiationException e) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);
        } catch (ClassNotFoundException e) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);

        } catch (IllegalAccessException e) {
            logger.error("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            throw new EAuthException(CMS.getUserMessage("CMS_ACL_CLASS_LOAD_FAIL", className), e);
        }
    }

    /**
     * Add an authentication manager instance.
     *
     * @param name name of the authentication manager instance
     * @param authMgr the authentication manager instance to be added
     */
    public void add(String name, IAuthManager authMgrInst) {
        mAuthMgrInsts.put(name, new AuthManagerProxy(true, authMgrInst));
    }

    /**
     * Removes a authentication manager instance.
     * @param name name of the authentication manager
     */
    public void delete(String name) {
        mAuthMgrInsts.remove(name);
    }

    /**
     * Gets the authentication manager instance of the specified name.
     *
     * @param name name of the authentication manager instance
     * @return the named authentication manager instance
     */
    public IAuthManager get(String name) {
        AuthManagerProxy proxy = mAuthMgrInsts.get(name);

        if (proxy == null)
            return null;
        return proxy.getAuthManager();
    }

    /**
     * Enumerate all authentication manager instances.
     */
    public Enumeration<IAuthManager> getAuthManagers() {
        Vector<IAuthManager> inst = new Vector<IAuthManager>();
        Enumeration<String> e = mAuthMgrInsts.keys();

        while (e.hasMoreElements()) {
            IAuthManager p = get(e.nextElement());

            if (p != null) {
                inst.addElement(p);
            }
        }
        return (inst.elements());
    }

    /**
     * Enumerate all registered authentication manager plugins.
     */
    public Enumeration<AuthMgrPlugin> getAuthManagerPlugins() {
        return (mAuthMgrPlugins.elements());
    }

    /**
     * retrieve a single auth manager plugin by name
     */
    public AuthMgrPlugin getAuthManagerPluginImpl(String name) {
        return mAuthMgrPlugins.get(name);
    }

    /**
     * Retrieve a single auth manager instance
     */

    /* getconfigparams above should be recoded to use this func */
    public IAuthManager getAuthManagerPlugin(String name) {
        AuthMgrPlugin plugin = mAuthMgrPlugins.get(name);
        String classpath = plugin.getClassPath();
        IAuthManager authMgrInst = null;

        try {
            authMgrInst = (IAuthManager) Class.forName(classpath).newInstance();
            return (authMgrInst);
        } catch (Exception e) {
            logger.warn("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_NOT_CREATED", e.toString()), e);
            return null;
        }
    }

    /**
     * Retrieves id (name) of this subsystem.
     *
     * @return name of the authentication subsystem
     */
    public String getId() {
        return (mId);
    }

    /**
     * Sets id string to this subsystem.
     * <p>
     * Use with caution. Should not do it when sharing with others
     *
     * @param id name to be applied to an authentication sybsystem
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * registers the administration servlet with the administration subsystem.
     */
    public void startup() throws EBaseException {
        //remove the log since it's already logged from S_ADMIN
        //String infoMsg = "Auth subsystem administration Servlet registered";
        //logger.info("AuthSubsystem: " + infoMsg);
    }

    /**
     * shuts down authentication managers one by one.
     * <P>
     */
    public void shutdown() {
        for (AuthManagerProxy proxy : mAuthMgrInsts.values()) {

            IAuthManager mgr = proxy.getAuthManager();

            logger.info("AuthSubsystem: " + CMS.getLogMessage("CMSCORE_AUTH_INSTANCE_SHUTDOWN", mgr.getName()));

            mgr.shutdown();
        }
        mAuthMgrPlugins.clear();
        mAuthMgrInsts.clear();
    }

    /**
     * Get a hashtable containing all authentication plugins.
     *
     * @return all authentication plugins.
     */
    public Hashtable<String, AuthMgrPlugin> getPlugins() {
        return mAuthMgrPlugins;
    }

    /**
     * Get a hashtable containing all authentication instances.
     *
     * @return all authentication instances.
     */
    public Hashtable<String, AuthManagerProxy> getInstances() {
        return mAuthMgrInsts;
    }

    /**
     * Returns the root configuration storage of this system.
     *
     * @return configuration store of this subsystem
     */
    public AuthenticationConfig getConfigStore() {
        return mConfig;
    }

    /**
     * gets the named authentication manager
     *
     * @param name of the authentication manager
     * @return the named authentication manager
     */
    public IAuthManager getAuthManager(String name) {
        return get(name);
    }
}
