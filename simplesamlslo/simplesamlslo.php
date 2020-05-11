<?php

/**
 * @package    simplesamlJoomla
 * @subpackage Plugins
 * @license    GNU/GPLv3
 * @copyright  Copyright 2020 Jonathan Richardson. All Rights Reserved.
 *
 *
 * This file is part of the SimpleSAMLphp Joomla plugin.
 *
 * The SimpleSAMLphp Joomla plugin is free software: you can redistribute it 
 * and/or modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation, either version 3 of the License, 
 * or (at your option) any later version.
 * 
 * The SimpleSAMLphp Joomla plugin is distributed in the hope that it will be 
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with miniOrange SAML plugin.  If not, see <http://www.gnu.org/licenses/>.
 */

defined('_JEXEC') or die;

/**
 * SimpleSAML Authentication Plugin
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
        $logouturl = $_SESSION['simplesaml_idp_slo'];
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
            $session->destroy();
            header('Location: ' . $logouturl, true, $permanent ? 301 : 302);
            exit();
        }
        return true;
    }

}
