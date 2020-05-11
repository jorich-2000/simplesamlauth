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
$simplesaml_idp_slo = '';

/**
 * SimpleSAML Authentication Plugin
 *
 */
class plgauthenticationsimplesamlsso extends JPlugin {

    /**
     * This method should handle any authentication and report back to the subject
     *
     * @param   array                   $credentials  Array holding the user credentials
     * @param   array                   $options      Array of extra options
     * @param   AuthenticationResponse  &$response    Authentication response object
     *
     * @return  void
     *
     * @since   1.5
     */
    public function onUserAuthenticate($credentials, $options, &$response) {
        // Load plugin language
        $this->loadLanguage();

        // check if backend authentication allowed
        if (JFactory::getApplication()->isClient('administrator') && !$this->params->get('simplesaml_backendlogin', 0)) {
            return;
        }

        $success = false;

        // check simplesaml config variable is set  
        $config_dir = filter_input(INPUT_SERVER, 'SIMPLESAMLPHP_CONFIG_DIR', FILTER_SANITIZE_STRING);
        if (!isset($config_dir)) {
            $response->type = 'simplesaml';
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_("PLG_SIMPLESAML_CONFIG_DIR_UNDEFINED");
        } else {

            // load simplesaml libraries
            require_once str_replace('/config', '/lib/_autoload.php', $config_dir);

            // $saml_auth->login();   
            $as = new \SimpleSAML\Auth\Simple($this->params->get('simplesaml_authsource', 'default-sp'));

            // set the logout url as a session variable if it is required 
            if ($this->params->get('simplesaml_slo')) {
                $_SESSION['simplesaml_idp_slo'] = $as->getLogoutURL($URL_AFTER_LOGOUT);
            } else {
                $_SESSION['simplesaml_idp_slo'] = '';
            }

            // Do the SSO login
            $as->requireAuth();

            jimport('joomla.user.authentication');
            $authenticate = JAuthentication::getInstance();
            $response = new JAuthenticationResponse();

            if (!$as->isAuthenticated()) {
                $errors = $as->getErrors();
                $response->type = 'simplesaml';
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = 'NOT_AUTHENTICATED';
            }
            $attrs = $as->getAttributes();

            $username = '';
            $email = '';
            $name = '';

            if (empty($attrs)) {
                $username = $as->getNameId();
                $email = $username;
            } else {
                $nameMapping = $this->params->get('simplesaml_attr_mapping_name');
                $usernameMapping = $this->params->get('simplesaml_attr_mapping_username');
                $mailMapping = $this->params->get('simplesaml_attr_mapping_mail');
                $groupsMapping = $this->params->get('simplesaml_attr_mapping_groups');
                if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])) {
                    $username = $attrs[$usernameMapping][0];
                }
                if (!empty($mailMapping) && isset($attrs[$mailMapping]) && !empty($attrs[$mailMapping][0])) {
                    $email = $attrs[$mailMapping][0];
                }
                if (!empty($nameMapping) && isset($attrs[$nameMapping]) && !empty($attrs[$nameMapping][0])) {
                    $name = $attrs[$nameMapping][0];
                }
                if (!empty($groupsMapping) && isset($attrs[$groupsMapping]) && !empty($attrs[$groupsMapping])) {
                    $saml_groups = $attrs[$groupsMapping];
                } else {
                    $saml_groups = array();
                }
            }

            $matcher = $this->params->get('simplesaml_account_matcher', 'username');

            if (empty($username) && $matcher == 'username') {
                $response->type = 'simplesaml';
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = 'NO_USERNAME';
            }
            if (empty($email) && $matcher == 'mail') {
                $response->type = 'simplesaml';
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = 'NO_MAIL';
            }

            $result = get_user_from_joomla($matcher, $username, $email);

            if (!$result) {
                // User not found, check if should be created
                $autocreate = $this->params->get('simplesaml_autocreate');

                if ($autocreate) {
                    if (empty($username)) {
                        $username = $email;
                    }

                    // user data
                    $data['name'] = (isset($name) && !empty($name)) ? $name : $username;
                    $data['username'] = $username;
                    $data['email'] = $data['email1'] = $data['email2'] = JStringPunycode::emailToPunycode($email);
                    $data['password'] = $data['password1'] = $data['password2'] = JUserHelper::genRandomPassword();

                    $result = get_user_from_joomla($matcher, $username, $email);

                    $user = JFactory::getUser();
                    $isroot = $user->authorise('core.admin');
                    if (!$isroot) {
                        if (!$user->bind($data)) {
                            throw new Exception("PLG_SIMPLESAML_ERROR_NO_BIND" . $user->getError());
                        }
                        $user->bind($data);
                        $user->set('block', '0');
                        $user->set('activation', '');

                        //Write to database
                        if (!$user->save()) {
                            throw new Exception("PLG_SIMPLESAML_ERROR_NO_SAVE" . $user->getError());
                        }

                        $groups = get_mapped_groups($this->params, $saml_groups);
                        if (empty($groups)) {
                            $params = JComponentHelper::getParams('com_users');
                            // Get the default new user group, Registered if not specified.
                            $system = $params->get('new_usertype', 2);
                            $groups[] = $system;
                        }

                        $user->set('groups', $groups);
                        $user->groups = $groups;
                        //Write to database
                        if (!$user->save()) {
                            throw new Exception("PLG_SIMPLESAML_ERROR_NO_SAVE" . $user->getError());
                        }
                    } else {
                        JFactory::getApplication()->enqueueMessage(JText::_('PLG_SIMPLESAML_ERROR_NO_SAVE_SU'), 'Notice');
                    }


                    $response->type = 'simplesaml';
                    $response->email = $data['email'];
                    $response->fullname = $data['name'];
                    $response->username = $data['username'];
                    $response->status = JAuthentication::STATUS_SUCCESS;
                } else {
                    $response->type = 'simplesaml';
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->error_message = 'PLG_SIMPLESAML_ERROR_NO_USER';
                }
            } else {
                $user = JFactory::getUser($result->id);

                // User found, check if data should be updated
                $autoupdate = $this->params->get('simplesaml_updateuser');
                $isroot = $user->authorise('core.admin');
                if (!$isroot) {
                    if ($autoupdate) {
                        // TODO Update
                        if (isset($name) && !empty($name)) {
                            $user->set('name', $name);
                            $user->save();
                        }

                        $groups = get_mapped_groups($this->params, $saml_groups);
                        if (!empty($groups)) {
                            $user->set('groups', $groups);
                            if (!$user->save()) {
                                throw new Exception("PLG_SIMPLESAML_ERROR_NO_SAVE" . $user->getError());
                            }
                        }
                    }
                } else {
                    JFactory::getApplication()->enqueueMessage(JText::_('PLG_SIMPLESAML_ERROR_NO_SAVE_SU'), 'Notice');
                }
			   

                $response->type = 'simplesaml';
                // Reset the username to what we ended up using
                $response->username = $user->username;
                $response->fullname = $name;
                $response->email = $email;
                $response->status = JAuthentication::STATUS_SUCCESS;
                $response->error_message = '';
            }
        }
    }

}

function get_user_from_joomla($matcher, $username, $email) {
    // Get a database object
    $db = JFactory::getDbo();

    switch ($matcher) {
        case 'mail':
            $query = $db->getQuery(true)
                    ->select('id')
                    ->from('#__users')
                    ->where('email=' . $db->quote($email));
            break;
        case 'username':
        default:
            $query = $db->getQuery(true)
                    ->select('id')
                    ->from('#__users')
                    ->where('username=' . $db->quote($username));
            break;
    }

    $db->setQuery($query);
    $result = $db->loadObject();
    return $result;
}

function get_mapped_groups($saml_params, $saml_groups) {
    $groups = array();

    if (!empty($saml_groups)) {
        $saml_mapped_groups = array();
        $i = 1;
        while ($i < 21) {
            $saml_mapped_groups_value = $saml_params->get('group' . $i . '_map');
            $saml_mapped_groups[$i] = explode(',', $saml_mapped_groups_value);
            $i++;
        }
    }

    foreach ($saml_groups as $saml_group) {
        if (!empty($saml_group)) {
            $i = 0;
            while ($i < 21) {
                if (!empty($saml_mapped_groups[$i]) && in_array($saml_group, $saml_mapped_groups[$i])) {
                    $groups[] = $saml_params->get('group' . $i);
                }
                $i++;
            }
        }
    }

    return array_unique($groups);
}
