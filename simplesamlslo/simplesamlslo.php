<?php

/**
 * @package    SimpleSAMLAuth.Administrator
 * @subpackage SimpleSAMLslo
 * @license    GNU/GPLv3
 * @copyright  Copyright 2020 Jonathan Richardson. All Rights Reserved.
 *
 * The SimpleSAMLAuth package is free software: you can redistribute it 
 * and/or modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation, either version 3 of the License, 
 * or (at your option) any later version.
 * 
 * The SimpleSAMLAuth package is distributed in the hope that it will be 
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with miniOrange SAML plugin.  If not, see <http://www.gnu.org/licenses/>.
 */
defined('_JEXEC') or die;

/**
 * Single Log Out using SimpleSAML User.Plugin
 *
 */
class plgusersimplesamlslo extends JPlugin {

    /**
     * Application object
     *
     * @var    JApplicationCms
     * @since  3.2
     */
    protected $app;

    /**
     * Database object
     *
     * @var    JDatabaseDriver
     * @since  3.2
     */
    protected $db;

    public function onUserLogout($user, $options = array()) {
        // check simplesaml config variable is set  
        $config_dir = filter_input(INPUT_SERVER, 'SIMPLESAMLPHP_CONFIG_DIR', FILTER_SANITIZE_STRING);
        if (isset($config_dir)) {

            // load simplesaml libraries
            require_once str_replace('/config', '/lib/_autoload.php', $config_dir);

            // Get parameters from the simplesamlsso authentication login plugin
            $plugin = JPluginHelper::getPlugin('authentication', 'simplesamlsso');

            // Check if plugin is enabled
            if ($plugin) {
                // Get plugin params
                $pluginParams = new JRegistry($plugin->params);

                $simplesaml_slo = $pluginParams->get('simplesaml_slo',0);
                $simplesaml_authsource = $pluginParams->get('simplesaml_authsource', 'default-sp');
            }
            $as = new \SimpleSAML\Auth\Simple($simplesaml_authsource);
            
            // only set logout url if option is set to enable single logout
            if ($simplesaml_slo == 1) {
                $logouturl = $as->getLogoutURL();
            }
            
            $my = JFactory::getUser();
            $session = JFactory::getSession();

            // Make sure we're a valid user first
            if ($user['id'] == 0 && !$my->get('tmp_user')) {
                return true;
            }

            $sharedSessions = $this->app->get('shared_session', '0');

            // Check to see if we're deleting the current session
            if ($my->id == $user['id'] && ($sharedSessions || (!$sharedSessions && $options['clientid'] == $this->app->getClientId()))) {
                // Hit the user last visit field
                $my->setLastVisit();

                // Destroy the php session for this user
                $session->destroy();
            }

            // Enable / Disable Forcing logout all users with same userid
            $forceLogout = $this->params->get('forceLogout', 1);

            if ($forceLogout) {
                $query = $this->db->getQuery(true)
                        ->delete($this->db->quoteName('#__session'))
                        ->where($this->db->quoteName('userid') . ' = ' . (int) $user['id']);

                if (!$sharedSessions) {
                    $query->where($this->db->quoteName('client_id') . ' = ' . (int) $options['clientid']);
                }

                try {
                    $this->db->setQuery($query)->execute();
                } catch (RuntimeException $e) {
                    return false;
                }
            }

            // Delete "user state" cookie used for reverse caching proxies like Varnish, Nginx etc.
            if ($this->app->isClient('site')) {
                $this->app->input->cookie->set('joomla_user_state', '', 1, $this->app->get('cookie_path', '/'), $this->app->get('cookie_domain', ''));
            }

            if (!empty($logouturl)) {
                \SimpleSAML\Session::getSessionFromRequest()->cleanup();
                $session->destroy();
                header('Location: ' . $logouturl, true, $permanent ? 301 : 302);
                exit();
            }
            return true;
        }
    }

}
