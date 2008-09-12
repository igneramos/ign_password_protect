//<?php
// This is a PLUGIN TEMPLATE.

// Copy this file to a new name like abc_myplugin.php. Edit the code, then
// run this file at the command line to produce a plugin for distribution:
// $ php abc_myplugin.php > abc_myplugin-0.1.txt


// 0 = Plugin help is in Textile format, no raw HTML allowed (default).
// 1 = Plugin help is in raw HTML. Not recommended.
$plugin['allow_html_help'] = 1;

$plugin['name'] = 'ign_password_protect';
$plugin['version'] = '0.5b10';
$plugin['author'] = 'Jeremy Amos';
$plugin['author_uri'] = 'http://www.igneramos.com';
$plugin['description'] = 'Password protect articles or sections; authenticates against txp_users or alternate database (ign_users) ';

// Plugin types:
// 0 = regular plugin; loaded on the public web side only
// 1 = admin plugin; loaded on both the public and admin side
// 2 = library; loaded only when include_plugin() or require_plugin() is called
$plugin['type'] = '1';

if (!defined('txpinterface'))
 @include_once('zem_tpl.php');

# --- BEGIN PLUGIN CODE ---

/*------------------------------------
Portions of this code Copyright 2004 by Dean Allen. All rights reserved.
Use of this software denotes acceptance of the Textpattern license agreement

Copyright 2005-2006 by Jeremy Amos. All rights reserved.
Use of this plugin denotes acceptance of the Textpattern license agreement
------------------------------------*/

//-----------------------------------------------

// user editable settings

//Define privilege levels
 global $ign_levels, $ign_privs, $ign_err;

 $ign_levels = array(
	 1 => 'Level 1',
	 2 => 'Level 2',
	 3 => 'Level 3',
	 4 => 'Level 4',
	 5 => 'Level 5',
	 6 => 'Level 6',
	 0 => gTxt('none')
 );

 // define privs for tab and tab-functions, privs tied to txp_user privs for current admin area user
 $ign_privs = array(
	 'tab' => '1,2,3,4',
	 'new_user' => '1,2,3',
	 'reset_pass' => '1,2,3',
	 'change_pass' => '1,2,3,4',
	 'edit_users' => '1,2,3,4'
 );

 $ign_error_codes = array(
	 'success' => 0,
	 'logout' => 1,
	 'auth' => 2,
	 'cookie' => 3,
	 'privs' => 4
 );

// Default message text
define('IGN_LOGIN_ERR','Sorry, the username and/or password entered is not valid, or you do not have privileges to access this resource.');
define('IGN_LOGOUT_LINK', 'Click here to logout.');

/* this is needed for installations where REQUEST_URI is not avaliable - thanks to Dave Harper www.hikebox.com*/
if (empty($_SERVER['REQUEST_URI'])) {
			 if (!empty($_SERVER['SCRIPT_NAME'])) {
				 $_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'];
			 } else if (!empty($_SERVER['PHP_SELF'])) {
				 $_SERVER['REQUEST_URI'] = $_SERVER['PHP_SELF'];
} else if (!empty($_ENV['PATH_INFO'])) {
							 $_SERVER['REQUEST_URI'] = $_SERVER['PATH_INFO'];
			 }
}

//-----------------------------------------------
/**
 * Returns string, used for localization, much of this is deprecated, content moved to forms to allow easier localization
 *
 *
 **/
 function ign_gTxt($what)
 {

	 $lang = array(
		 'manage_users' => 'Manage Users',
		 'user_db' => 'Use Alternate Database?',
		 'users' => 'Users',
		 'add_new_user' => 'Add New User',
		 'could_not_update_user' => 'Could not update user',
		 'reset_user_password' => 'Reset User Password',
		 'error_adding_new_user' => 'Could not add new user',
		 'new_pass' => 'Enter new password',
		 'confirm_pass' => 'Re-enter new password to confirm',
		 'a_message_will_be_sent_with_login' => 'A message will be sent with login information',
		 'email_pass' => 'Mail it to me',
		 'fallback' => 'Also authenticate against txp_users?',
		 //for email confirmations, values available are:
		 //1 - real name
		 //2 - user name
		 //3 - password
		 //4 - site name
		 //5 - site url
		 // see http://www.php.net/sprintf for more information on how to format the string
		 'new_user_email' => "Dear %1\$s,\r\n\r\nYou have been registered as a user of %4\$s.\r\nYour username is: %2\$s\r\nYour password is: %3\$s\r\n\r\nVisit the site at %5\$s",
		 'change_email' => "Dear %1\$s,\r\n\r\nYour password has been changed. Your new password is: %3\$s\r\n\r\nVisit the site at %5\$s"
	 );

	 return $lang[$what];
 }

//--------------do not edit below this line------------------

//generate admin interface
if (txpinterface == 'admin')
{
 if(!isset($prefs['ign_pp_version']) || $prefs['ign_pp_version'] != $plugins_ver['ign_password_protect'])
 {
	 //TODO: Update Prefs, run forms check and install forms if necessary.
	 //TODO: add form pref for designating an alternate form
 }
 if (empty($prefs['ign_user_db']))
 {
	 ign_pp_install();
 }

 //assign privs for interfaces
 add_privs('ign_user_mgmt', '1,2,3,4');

 //create tabs, register callback functions for those tabs
 register_tab('admin', 'ign_user_mgmt', ign_gtxt('manage_users'));
 register_callback('ign_manageUsers', 'ign_user_mgmt');

 register_callback('ign_file_tab','file','file_edit');
}

if (txpinterface == 'public')
{
 // disable caching for all pages
 // FIXME: find more selective method for disabling caching

 header("Cache-Control: must-revalidate");
 $prefs['send_lastmod'] = false;

 //register file_download callback to filter download requests
 register_callback('ign_filter_downloads', 'file_download');

 //fire off validation routine, since most functionality is dependent on it:
 $ign_err = ign_doTxpValidate();
}

//---------------------public tags--------------------------

//-----------------------------------------------
/**
 * Wrap content to protect, deprecated, use ign_login_form and ign_if_logged_in constructs instead if possible
 *
 *
 **/
 function ign_password_protect($atts, $thing='')
 {
	 if(empty($thing)) $atts['login_type']='page';
	 $out = ign_doAuth($atts, $thing);
	 if($out) return $out;
 }

//-----------------------------------------------
/**
 * Displays currently logged-in user
 *
 *
 **/
 function ign_current_user($atts)
 {
	 global $ign_user, $ign_err;

	 extract(lAtts(array(
		 'display' => 'name',
		 'verbose' => false,
		 'greeting' => gtxt('logged_in_as'),
		 'form' => 'current_user'
	 ), $atts, 0));

	 if ( !$ign_err ) {
		 $use_form = @fetch_form($form);
		 if(empty($use_form))
		 {
			 $use_form = ign_default_form('current_user');
		 }
		 return parse($use_form);
	 } else {
		 return false;
	 }
 }

//-----------------------------------------------
/**
 * display login form
 *
 *
 **/
 function ign_show_login($atts)
 {
	// FIXME: Fix form presentation when calling current user
	// currently takes the form passed in for login.
	// options to solve this are:
	// 1. use the show_logged param to pass in a new form
	// 2. add a conditional to the forms to determine whether a user's logged in or not
	 global $ign_user, $ign_err;

	 $logout = gps('logout');

	 extract(lAtts(array(
		 'show_logged'=> 'true'
		 ),$atts, 0)
	 );

	 if ($ign_user) {
		 $out = (strtolower($show_logged)=='true' || $show_logged==1) ? ign_current_user($atts) : '';
	 } else {
		 $out = ign_doLoginForm($atts);
	 }
	 return $out;
 }

//-----------------------------------------------
/**
 * Returns list of active users
 *
 *
 **/
 // FIXME: Move this to a form?
 function ign_active_users($atts, $thing='')
 {
	 global $ign_user_db;
	 extract(lAtts(
		 array(
			 'privs' => '',
			 'display' => 'name',
			 'wraptag' => 'p',
			 'break' => 'br',
			 'class' => '',
		 ), $atts, 0));

		 $match = array('/[^0-9\,]/', '/\,\,/', '/\,$/');
	 $replacement = array('',',');
	 $privs = preg_replace($match, $replacement, $privs);
	 if(strtolower($display) != 'realname') {
		 $display = 'name';
	 }
	 $sql = '';
	 if(!empty($privs)) {
		 $sql .= "privs in ($privs) and ";
	 }
	 $sql .= "last_access > date_add(now(), interval -2 minute)";

	 $r = safe_rows($display, $ign_user_db, $sql);

	 if(count($r) < 1) {
				 return false;
		 } else {
		 foreach($r as $user) {
			 $users[] = $user[$display];
		 }
		 $out = !empty($thing) ? $thing : '';
		 return $out.n.doWrap($users, $wraptag, $break, $class).n;
		 }
 }

//-----------------------------------------------
/**
 * Tag for creating a public self-edit form to allow end users to change their password
 *
 *
 **/
 function ign_self_edit($atts)
 {
	 global $ign_user_db, $ign_user, $ign_err, $ign_use_custom, $step;

	 extract(lAtts(array(
		 'form' => 'self_edit_form',
			 ), $atts, 0)
	 );

	 //requires custom db (doesn't work on txp_users)
	 if (!$ign_use_custom) return ''; //exit if not ign_use_custom

	 $step = gps('step');

	 //check if user is logged in
	 if (!empty($ign_user))
	 {
		 if (!empty($step) && $step == 'ign_update_self')
		 {
			 //do update routine
			 $out = ign_update_self($atts);
			 return $out;
		 }

			 list($form_action) = explode('?', $_SERVER['REQUEST_URI']);

			 $use_form = @fetch_form($form);
			 if(empty($use_form) || $use_form == "<p>form <strong>$form</strong> does not exist</p>")
			 {
				 $use_form = ign_default_form('self_edit');
			 }

		 return
			 "<form action='{$form_action}' method='post'>".
			 eInput('ign_self_edit'). n .sInput('ign_update_self').
			 n.parse($use_form).n.
			 '</form>';

	 }
	 return '';
 }

//-----------------------------------------------
/**
 * Conditional tag, displays content if user is not logged in, can be deprecated?
 *
 *
 **/
 function ign_if_not_logged_in($atts,$thing)
 {
	 global $ign_user, $ign_err;

	 if (!empty($ign_user))
	 {
		 return '';
	 }

	 return parse($thing);
 }

//-----------------------------------------------
/**
 * Conditional tag, shows or hides content depending on user's logged status
 *
 *
 **/
 function ign_if_logged_in($atts, $thing)
 {
	 global $ign_user, $ign_page_privs;

	 extract(lAtts(array(
		 'privs' => ''
	 ), $atts, 0));

	 if (empty($privs) && !empty($ign_page_privs))
	 {
		 $privs = $ign_page_privs;
	 }

	 //eval privs
	 $out = (!empty($ign_user)) ?
		 parse ( evalelse ( $thing, ( ign_checkPrivs($privs) ))) :
		 parse ( evalelse ( $thing, false ));

	 return $out;
 }

//-----------------------------------------------
/**
 * Tag to set page-wide privileges
 * accepts comma delimited string of integers
 *
 *
 **/
 function ign_page_privs($atts)
 {
	 global $ign_page_privs;

	 extract(lAtts(array(
		 'privs' => ''
	 ), $atts, 0));

	 $ign_page_privs = $privs;

 }

//---------------------internal functions--------------------------


//-----------------------------------------------
/**
 * Fires off validation routine OR forces browser to request credentials
 *
 *
 **/
 function ign_doAuth($atts, $thing)
 {
	 global $ign_user, $ign_err, $ign_page_privs;

	 extract(lAtts(array(
		 'hide_login' => 0,
		 'show_err' => 0,
		 'login_type' => '',
		 'login_msg' => '',
		 'err_msg' => '',
		 'privs' => ''
		 ), $atts, 0));

	 if (!empty($ign_page_privs) && empty($privs))
	 {
		 $privs = $ign_page_privs;
	 }

	 if($ign_user && ign_checkPrivs($privs)) {
		 $out[] = parse($thing);

		 return parse($thing);
	 } else { //invalid user or privs
		 switch ($login_type) {
			 case 'page':
				 header('WWW-Authenticate: Basic realm="Private"');
				 header('HTTP/1.0 401 Unauthorized');
				 exit(gTxt('auth_required'));
			 default:
				 $out = (!$hide_login) ? ign_doLoginForm($atts) : '';
				 return $out;
				 break;
		 }
	 }
 }

// -------------------------------------------------------------
/**
 * ign_doTxpValidate strictly validates cookie or passed in credentials, does NOT check privilege levels,
 * make certain to call ign_checkPrivs after validating the user for protected elements
 * returns value depending type of failure or 0 on success
 * 0 - successful validation
 * 1 - logout process (display login?)
 * 2 - invalid user / password
 * 3 - bad cookie
 *
 **/
 function ign_doTxpValidate()
 {
	 global $logout, $txpcfg, $ign_user_db;

	 if(!empty($_SERVER['PHP_AUTH_USER']) && !empty($_SERVER['PHP_AUTH_PW'])) //if credentials are being passed in from browser
	 {
		 $p_userid = serverSet('PHP_AUTH_USER');
		 $p_password = serverSet('PHP_AUTH_PW');
	 } else {
		 $p_userid = ps('p_userid');
		 $p_password = ps('p_password');
	 }

	 $logout = gps('logout');
	 $stay = ps('stay');
	 $now = time()+3600*24*365;
	 // $d = explode('.', $_SERVER['HTTP_HOST']);
	 // $d = '.' . join('.', array_slice($d, 1-count($d), count($d)-1));
	$domain = ign_getDomain();

	 if ($logout) {
		 setcookie('ign_login',' ',time()-3600,'/', $domain);
		 $GLOBALS['ign_user'] = '';
		 // logout from Vanilla
			 if(load_plugin("ddh_vanilla_integration"))
		 {
			 ddh_vanilla_logout();
			 }
		 return 1;
	 }

	 if (isset($_COOKIE['ign_login']) and !$logout) // cookie exists
	 {
		 //parse cookie
		 list($c_userid,$c_privs,$c_realname, $cookie_hash) = ign_getCookie();

		 //get account info
		 $acct = safe_row('name, privs, realname, nonce, last_access, email', $ign_user_db, "name='$c_userid'");
		 $nonce = $acct['nonce'];

		 if (md5($c_userid.$c_privs.$nonce) == $cookie_hash) {	 // check nonce
			 $GLOBALS['ign_user'] = $c_userid; // cookie is good, create $txp_user
			 if($c_privs != $acct['privs']) //if privs have changed since cookie was created
			 {
				 if ($_COOKIE['ign_stay'])
				 {
					 if(!ign_setCookie($acct, $now)) return 3;
				 } else {
					 if(!ign_setCookie($acct)) return 3;
				 }
			 }
			 ign_update_access($acct);
			 return 0;
		 } else {
			 // something's gone wrong
			 $GLOBALS['ign_user'] = '';
			 setcookie('ign_login','',-1, '/');
			 return 3;
		 }

	 } elseif ($p_userid) { // no cookie, but incoming login vars

			 sleep(3); // should grind dictionary attacks to a halt

			 $valid_usr = ign_validate($p_userid,$p_password);

			 if ($valid_usr) {
				 $nonce = $valid_usr['nonce'];	 //get nonce

				 if ($stay) { // persistent cookie required
					 if(!ign_setCookie($valid_usr, $now)) return 3;
					 setcookie('ign_stay', '1', $now, '/', $domain);
				 } else {			 // session-only cookie required`
					 if(!ign_setCookie($valid_usr)) return 3;
					 setcookie('ign_stay','0',-1, '/', $domain);
				 }
				 $GLOBALS['ign_user'] = $p_userid; // login is good, create $txp_user
				 return 0;
			 } else {
				 $GLOBALS['ign_user'] = '';
				 return 2;
			 }

	 } else {
		 $GLOBALS['ign_user'] = '';
		 return -1;
	 }
 }
// -------------------------------------------------------------
 function ign_validate($user,$password)
 {
	 global $ign_user_db, $prefs;

	 $fallback = false;
	 $safe_user = addslashes($user);
	 $safe_pass = doSlash($password);
	 $sql = "name = '$safe_user' and pass = password(lower('$safe_pass')) ";

	 $r = safe_row("name, realname, privs, nonce, last_access, email", $ign_user_db, $sql);
	 if (!$r) // fallback to old_password()
	 {
		 $fallback = true;
		 $sql = "name = '$safe_user' and (pass = old_password(lower('$safe_pass')) or pass = old_password('$safe_pass')) ";
		 $r = safe_row("name, realname, privs, nonce, last_access, email", $ign_user_db, $sql);
		 if(!$r && $prefs['ign_use_custom'] == 1) // last-ditch fallback to txp_users if using custom db AND flag is set.
		 {
			 $sql = "name = '$safe_user' and ( pass = password(lower('$safe_pass')) or pass = old_password(lower('$safe_pass')) or pass = old_password('$safe_pass') )";
			 $r = safe_row("name, realname, privs, nonce, last_access, email", 'txp_users', $sql);
		 }
	 }
	 if ($r)
	 {
		 if ($fallback) //update pass to the new hash structure ?
		 {
			 safe_update($ign_user_db, "pass = password(lower('$password'))", "name='$user'");
		 }
		 // Create session & cookies for Vanilla forum
		 if(load_plugin("ddh_vanilla_integration")) {
			 ddh_vanilla_login($safe_user, $password);
		 }

		 ign_update_access($r);
		 return $r;
	 }
	 return false;
 }

 function ign_filter_downloads() //callback routine called by file_download
 {
	global $id, $file_error, $ign_user, $pretext, $s;

	if(empty($id)) {
		//no $id means we need to reparse the URL...
		extract($pretext);
		if($prefs['permlink_mode']=='messy') {
			$id = gps('id'); //get $id from GET
		} else { //we need to parse the uri
			extract(chopurl($_SERVER['REQUEST_URI']));
			$id = $u2; //should probably test for failure here...
		}
	}

	//let's check to see if this file has permissions set and get the category
	$file = safe_row('permissions, category', 'txp_file', "id='$id'");
	$parent = (!empty($file['category'])) ? safe_field('parent','txp_category', "name='{$file['category']}'") : '';
	if(!empty($file['permissions'])) // permissions set, carry on
	{
		if(empty($ign_user) || !ign_checkPrivs($file['permissions'])) //if any check fails, give 'em the boot
			$file_error = '403';
	} else if($parent == 'client'){ 	// let's fire off a quick category comparison for client-specific setups...
		if(empty($ign_user) || $file['category'] != $ign_user)
			$file_error = '403';
	}

	//return to let file_download do its thing...
	return;

 }

// -------------------------------------------------------------
 function ign_update_access($acct)
 {
	 global $ign_pp_updated, $ign_user, $ign_user_db;

	 if (!$ign_pp_updated) { //update last access if necessary
		 if(!empty($_COOKIE['ign_login']))
		 {
			 list(,,,,$cookie_time) = ign_getCookie();
			 if(strtotime($acct['last_access'])-strtotime($cookie_time) > 60) ign_setCookie($acct);
		 }
		 $safe_user = strtr(addslashes($ign_user),array('_' => '\_', '%' => '\%'));
		 safe_update($ign_user_db, "last_access = now()", "name = '$safe_user'");
		 $ign_pp_updated = true;
	 }
 }

// -------------------------------------------------------------
 function ign_checkPrivs($privs)
 {
	 global $ign_err;

	 if(!empty($privs) && preg_match('/[0-9]+/', $privs)) //if privs attribute is set and contains numerical values
	 {
		 $match = array('/[^0-9\,]/', '/\,\,/', '/\,$/');
		 $replacement = array('',',');
		 $privs = preg_replace($match, $replacement, $privs);
		 $privs = explode(',', $privs);
	 }

	 ign_stopCache();

	 list($c_userid,$c_privs,$c_realname, $cookie_hash,) = ign_getCookie();
	 if (empty($privs) || in_array($c_privs, $privs))
	 {
		 return true;
	 }

	 $ign_err = 4;
	 return false;
 }

// -------------------------------------------------------------
 function ign_createDb()
 {
	 global $txpcfg;
	 //function to create database
	 $version = mysql_get_server_info();

	 $dbcharset = $txpcfg['dbcharset'];

	 //Use "ENGINE" if version of MySQL > (4.0.18 or 4.1.2)
	 $tabletype = ( intval($version[0]) >= 5 || preg_match('#^4\.(0\.[2-9]|(1[89]))|(1\.[2-9])#',$version))
					 ? " ENGINE=MyISAM "
					 : " TYPE=MyISAM ";
	 // On 4.1 or greater use utf8-tables
	 if ( isset($dbcharset) && (intval($version[0]) >= 5 || preg_match('#^4\.[1-9]#',$version)))
	 {
		 $tabletype .= " CHARACTER SET = $dbcharset ";
		 if (isset($dbcollate))
			 $tabletype .= " COLLATE $dbcollate ";
		 mysql_query("SET NAMES ".$dbcharset);
	 }

	 $create_sql = "CREATE TABLE IF NOT EXISTS `".PFX."ign_users` (
			 `user_id` int(4) NOT NULL auto_increment,
			 `name` varchar(64) NOT NULL default '',
			 `pass` varchar(128) NOT NULL default '',
			 `RealName` varchar(64) NOT NULL default '',
			 `email` varchar(100) NOT NULL default '',
			 `privs` tinyint(2) NOT NULL default '1',
			 `last_access` datetime NOT NULL default '0000-00-00 00:00:00',
			 `nonce` varchar(64) NOT NULL default '',
			 PRIMARY KEY	 (`user_id`),
			 UNIQUE KEY `name` (`name`)
	 ) $tabletype PACK_KEYS=1 AUTO_INCREMENT=2 ";

	 $r = safe_query($create_sql);

	 $sql = "insert into ".PFX."ign_users (name, pass, RealName, email, privs, last_access, nonce)
	 select name, pass, RealName, email, privs, last_access, nonce from ".PFX."txp_users
	 where not exists (select name, pass, RealName, email, privs, last_access, nonce from ".PFX."ign_users where 1)";
	 $r = safe_query($sql);

 }

//-----------------------------------------------
 function ign_pp_install()
 {
	 if(!isset($ign_user_db)) //if no db defined, default to txp_users
	 {
		 $ign_user_db = 'txp_users';
		 if(safe_insert('txp_prefs', "prefs_id=1, name='ign_user_db', val='$ign_user_db', html='text_input'"))
		 {
			 $log[] = "User database set to {$ign_user_db}";
		 }
	 }
	 if(!isset($ign_use_custom))
	 {
		 if(safe_insert('txp_prefs', "prefs_id=1, name='ign_use_custom', val='0', html='yesnoradio'"))
		 {
			 $log[] = "Use custom database set to 0";
		 }
	 }

 }

//-----------------------------------------------
 function ign_update_prefs()
 {
	 global $ign_user_db;

	 $ign_use_custom = ps('ign_use_custom');
	 $ign_fallback = ps('fallback');
	 if($ign_use_custom == 1)
	 {
		 safe_update('txp_prefs', "val = 'ign_users'","name = 'ign_user_db'");
		 safe_update('txp_prefs', "val = 1", "name = 'ign_use_custom'");
		 safe_update('txp_prefs', 'val = 1', "name = 'ign_fallback'");
		 ign_createDb();
		 $ign_user_db = 'ign_users';
	 } elseif ($ign_use_custom == 0) {
		 safe_update('txp_prefs', "val = 'txp_users'", "name = 'ign_user_db'");
		 safe_update('txp_prefs', "val = 0", "name = 'ign_use_custom'");
		 safe_update('txp_prefs', 'val = 0', "name = 'ign_fallback'");
		 $ign_user_db = 'txp_users';
	 }
	 ign_admin('Database preference updated');
 }

//-----------------------------------------------
 function ign_useCustomDbForm()
 {
	 global $ign_user_db, $prefs;
	 extract(lAtts(array(
		 'ign_use_custom' => '',
		 'ign_fallback' => ''
		 ), $prefs, 0)
	 );
	 if(isset($_POST['ign_use_custom']))
	 {
		 $ign_use_custom = $_POST['ign_use_custom'];
	 } else {
		 $ign_use_custom = (empty($ign_use_custom)) ? '0' : $ign_use_custom;
	 }

	 return n.'<div style="margin: 3em auto auto auto; width: 40em; text-align: center;">'.
		 n.n.form(
		 n.eInput('ign_user_mgmt').
		 n.sInput('ign_update_prefs').
		 ign_gTxt('user_db').br.yesnoRadio('ign_use_custom',$ign_use_custom).
		 br.ign_gTxt('fallback').ign_checkbox(array('name'=>'fallback','checked'=>'true')).
		 br.
		 n.fInput('submit', 'ign_update_prefs', 'Update', 'smallerbox')
	 ).n.'</div>';
 }

//-----------------------------------------------
 function ign_manageUsers($event, $step) //
 {

	 global $ign_user_db, $ign_user, $txp_user, $myprivs, $ign_levels;

	 if ($event == 'ign_user_mgmt') {

		 require_privs('article.publish');

		 $myprivs = fetch('privs','txp_users','name',$txp_user);

		 if(!$step or !in_array($step,
			 array('ign_admin','ign_user_delete','ign_userList','ign_userSave','ign_userSaveNew','ign_changeEmail','ign_changePass', 'ign_update_prefs', 'ign_userChangePass')))
		 {
			 ign_admin();
		 } else $step();
	 }
 }


//-----------------------------------------------
 function ign_get_pref($pref) //selective preference retrieval
 {
	 global $ign_user_db;

	 $r = safe_field('val', $ign_user_db, 'prefs_id=1 and name=\'$pref\'');
	 if ($r) {
		 return $r;
	 }
	 return false;
 }

//-----------------------------------------------
// the following code is essentially lifted from txp_admin.php.

 function ign_admin($message='')
 {
	 global $myprivs,$ign_user, $ign_user_db, $ign_privs;

	 pagetop(ign_gTxt('manage_users'),$message);
	 $themail = fetch('email',$ign_user_db,'name',$ign_user);

	 $table_exists = safe_query("show table status like 'ign_users'");

	 echo ign_useCustomDbForm();

				 if ( $ign_user_db == 'ign_users' && $table_exists )
				 {
		 echo ign_userList();
		 echo (in_array($myprivs, explode(',', $ign_privs['new_user']))) ? ign_new_user_form(): '';
		 echo (in_array($myprivs, explode(',', $ign_privs['reset_pass']))) ? ign_resetUserPassForm() : '';
				 } else {
					 echo '<div align="center" style="margin-top:3em">User management functions only available here when using custom database.<br />Use <a href="?event=admin">site admin</a> tab instead.</div>';
				 }

 }

// -------------------------------------------------------------
 function ign_changeEmail()
 {
	 global $ign_user, $ign_user_db;
	 $new_email = gps('new_email');
	 if (safe_update($ign_user_db, "email	 = '$new_email'", "name = '$ign_user'")) {
		 ign_admin('email address changed to '.$new_email);
	 } else {
		 ign_admin('Failed to change email address.');
	 }
 }

// -------------------------------------------------------------
 function ign_userSave()
 {
	 global $ign_user_db;
	 extract(doSlash(psa(array('privs','user_id','RealName','email'))));
	 $rs = safe_update($ign_user_db,
		 "privs = $privs,
		 RealName = '$RealName',
		 email = '$email'",
		 "user_id='$user_id'");
	 if ($rs) ign_admin(messenger('user',$RealName,'updated'));
 }

// -------------------------------------------------------------
 function ign_changePass()
 {
	 global $ign_user, $ign_user_db;
	 $message = '';
	 $themail = fetch('email',$ign_user_db,'name',$ign_user);
	 if (!empty($_POST["new_pass"])) {
		 $NewPass = $_POST["new_pass"];
		 if (safe_update($ign_user_db, "pass = password(lower('$NewPass'))", "name='$ign_user'"))
		 {
			 $message .= gTxt('password_changed');
			 if ($_POST['mailpassword']==1) {
				 ign_sendNewPassword($NewPass,$themail,$ign_user);
				 $message .= sp.gTxt('and_mailed_to').sp.$themail;
			 }
			 $message .= ".";
		 } else echo comment(mysql_error());
		 ign_admin($message);
	 }
 }

// -------------------------------------------------------------
 function ign_userSaveNew()
 {
	 global $ign_user_db;

	 extract(doSlash(psa(array('privs','name','email','RealName'))));
	 $pw = ign_generatePassword(8);
	 $nonce = md5( uniqid( rand(), true ) );

	 if ($name) {
		 $rs = safe_insert(
			 $ign_user_db,
			 "privs			 = '$privs',
				 name				 = '$name',
				 email			 = '$email',
				 RealName = '$RealName',
				 pass				 =	 password(lower('$pw')),
				 nonce			 = '$nonce'"
		 );
	 }

	 if ($name && $rs) {
		 ign_send_password($pw,$email);
		 ign_admin(gTxt('password_sent_to').sp.$email);
	 } else {
		 ign_admin(ign_gTxt('error_adding_new_user'));
	 }
 }

// -------------------------------------------------------------
 function ign_privList($priv='')
 {
	 global $ign_levels;
	 return selectInput("privs", $ign_levels, $priv);
 }

// -------------------------------------------------------------
 function ign_getPrivLevel($priv)
 {
	 global $ign_levels;
	 return $ign_levels[$priv];
 }

// -------------------------------------------------------------
 function ign_send_password($pw,$email)
 {
	 global $sitename,$ign_user, $ign_user_db;
	 $myName = $ign_user;
	 extract(safe_row("RealName as myName, email as myEmail",
		 $ign_user_db, "name = '$myName'"));

		 $message = sprintf(ign_gTxt('new_user_email'), $_POST['RealName'], $_POST['name'], $pw, $sitename, hu);

	 return ignMail($email, "[$sitename] ".gTxt('your_login_info'), $message);
 }

// -------------------------------------------------------------
 function ign_sendNewPassword($NewPass,$themail,$name)
 {
	 global $ign_user, $ign_user_db, $sitename, $txp_user;

	 $realname = safe_field('realname', $ign_user_db, "name='$name'");
	 $message = sprintf(ign_gTxt('change_email'),$realname, $name, $NewPass, $sitename, hu);

	 return ignMail($themail, "[$sitename] ".gTxt('your_new_password'), $message);
 }

// -------------------------------------------------------------
 function ign_doLoginForm($atts)
 {
	 global $txpcfg, $ign_err;

	 extract(lAtts(array(
		 'hide_err' => 0,
		'id' => '',
		 'form' => 'login_form'
		 ), $atts, 0)
	 );

	 $use_form = @fetch_form($form);
	 if(empty($use_form) || $use_form == "<p>form <strong>$form</strong> does not exist</p>" )
	 {
	 		 $use_form = ign_default_form('login');
	 }

	 list($form_action) = explode('?', $_SERVER['REQUEST_URI']);

	 			// $id = (!empty($id)) ? " id=\"$id\"" : NULL;
	$qs = @$_SERVER['QUERY_STRING'];
	$qs = preg_replace('/&?logout=1/', '', $qs);

	 $login = (!empty($qs)) ? "<form action='{$form_action}?$qs' method='post'$id>" : "<form action='{$form_action}' method='post'$id>";
	 $login .= parse($use_form);
	 $login .= "</form>";

	 return $login;
 }

// -------------------------------------------------------------
 function ign_newPassForm()
 {
	 return '<div align="center" style="margin-top:3em">'.
	 form(
		 tag(gTxt('change_password'),'h3').
		 graf(gTxt('new_password').' '.
			 fInput('password','new_pass','','edit','','','20','1').
			 checkbox('mailpassword','1',1).gTxt('mail_it').' '.
			 fInput('submit','ign_changePass',gTxt('submit'),'smallerbox').
			 eInput('ign_user_mgmt').sInput('ign_changePass')
		 ,' style="text-align:center"')
	 ).'</div>';
 }

//-----------------------------------------------
	function ign_file_tab()
	{

		global $ign_levels;

		$id = gps('id');
		if(!empty($id))
			$r = safe_field('permissions','txp_file', "id = '$id'");

		$select = addslashes(selectInput('perms',$ign_levels, @$r));
		$select = str_replace("\n",'', $select);
		$select = str_replace("\t",'', $select);

		$js = "$(\"#file-status\" ).after(\"<fieldset><legend>Permissions</legend>$select</fieldset>\");";

		if(is_callable('script_js')) {
			echo script_js($js);
		}

		return;

	}

//-----------------------------------------------
/**
 * Process self-edit submission, returns success message or error
 **/
 function ign_update_self($atts)
 {
	 global $ign_user, $ign_user_db;
	 //process incoming post variables here
	 $new_pass = gps('new_pass');
	 $confirm_pass = gps('confirm_pass');
	 $email_pass = gps('email_pass');

	 $use_form = @fetch_form($form);
	 if(empty($use_form) || $use_form == "<p>form <strong>$form</strong> does not exist</p>" )
	{
		$use_form = ign_default_form('self_edit');
	}
	 if ($new_pass != $confirm_pass)
	 {
			 return "<span class='pass_error'>The supplied passwords do not match.</span>".$use_form;
	 }
	 if (empty($new_pass))
	 {
			 return "<span class='pass_error'>Password field cannot be blank.</span>".$use_form;
	 }
	 $r = safe_update('ign_users',"pass = password('$new_pass')", "name = '$ign_user'");
	 if ($r)
	 {
		 if ($email_pass){
			 $themail = fetch('email',$ign_user_db,'name',$ign_user);
			 list(,,$name,) = ign_getCookie();
			 $stuff = ign_sendNewPassword($new_pass, $themail, $name);
			 // return 'Password updated successfully!';
		 }
		return 'Password updated successfully!';
	 } else {
		 return 'Error encountered. Password not updated.';
	 }

 }

// -------------------------------------------------------------
 function ign_resetUserPassForm()
 {
	 global $myprivs,$ign_user_db;
	 $them = safe_rows_start("*",$ign_user_db,"1");

	 while ($a = nextRow($them)) {
		 $names[$a['name']] = $a['RealName'].' ('.$a['name'].')';
	 }
	 if (!empty($names)) {
		 return '<div align="center" style="margin-top:3em">'.
		 form(
			 tag(ign_gTxt('reset_user_password'),'h3').
			 graf(gTxt('a_new_password_will_be_mailed')).
				 graf(selectInput("name", $names, '',1).
				 fInput('submit','ign_changePass',gTxt('submit'),'smallerbox').
				 // eInput('ign_user_mgmt').sInput('ign_user_change_pass')
				 eInput('ign_user_mgmt').sInput('ign_userChangePass')
			 ,' style="text-align:center"')
		 ).'</div>';
	 }
 }

// -------------------------------------------------------------
 function ign_userChangePass()
 {
	 global $ign_user_db;
	 $name = ps('name');
	 $themail = safe_field("email",$ign_user_db,"name='".doSlash($name)."'");
	 $NewPass = ign_generatePassword(8);

	 $rs = safe_update($ign_user_db,"pass=password(lower('$NewPass'))",
		 "`name`='".doSlash($name)."'");

	 if ($rs) {
		 if (ign_sendNewPassword($NewPass,$themail,$name)) {
			 ign_admin(gTxt('password_sent_to').' '.$themail);
		 } else ign_admin(gTxt('could_not_mail').' '.$themail);
	 } else ign_admin(ign_gTxt('could_not_update_user').' '.$name);

 }

// -------------------------------------------------------------
 function ign_changeEmailForm($themail)
 {
	 return '<div align="center" style="margin-top:3em">'.
	 form(
		 tag(gTxt('change_email_address'),'h3').
		 graf(gTxt('new_email').' '.
			 fInput('text','new_email',$themail,'edit','','','20','2').
			 fInput('submit','ign_changeEmail',gTxt('submit'),'smallerbox').
			 eInput('ign_user_mgmt').sInput('ign_changeEmail')
		 ,' style="text-align:center"')
	 ).'</div>';
 }

// -------------------------------------------------------------
 function ign_userList()
 {
	 global $myprivs,$ign_user,$ign_user_db, $prefs, $ign_privs;

	 $allow_edit = (in_array($myprivs, explode(',', $ign_privs['edit_users']))) ? true : false;

	 if(version_compare($prefs['version'],'4.0.4') < 0) ign_add_paging();

	 //pagination code
	 $total = safe_count($ign_user_db, '1');

	 extract(gpsa(array('page','sort', 'dir', 'crit', 'search_method', 'last_access')));
	 $limit = 25;

	 $dir = ($dir == 'desc') ? 'desc' : 'asc';

	 switch($sort)
	 {
		 case 'name':
			 $sort_by = 'name';
		 break;

		 case 'email':
			 $sort_by = 'email';
		 break;

		 case 'privs':
			 $sort_by = 'privs';
		 break;

		 case 'last_access':
			 $sort_by = 'last_access';
		 break;

		 case 'realname':
		 default:
			 $sort_by = 'realname';
		 break;
	 }

	 $switch_dir = ($dir == 'desc') ? 'asc' : 'desc';

	 $criteria = 1;

	 list($page, $offset, $numPages) = pager($total, $limit, $page);

	 //build search here
	 //TODO: Implement search on user name / real name

	 $rs = safe_rows_start("*", $ign_user_db, "$criteria order by $sort_by $dir limit $offset, $limit");

	 $out[] = hed(ign_gTxt('users'),3,' align="center"');
	 $out[] = startTable('list');
	 $out[] = tr(
		 hCell(href(gTxt('real_name'), "index.php?event=ign_user_mgmt&step=list&page={$page}&dir={$switch_dir}&sort=real_name")).
		 hCell(href(gTxt('login_name'), "index.php?event=ign_user_mgmt&step=list&page={$page}&dir={$switch_dir}&sort=name")).
		 hCell(href(ucfirst(gTxt('email')), "index.php?event=ign_user_mgmt&step=list&page={$page}&dir={$switch_dir}&sort=email")).
		 hCell(href(gTxt('privileges'), "index.php?event=ign_user_mgmt&step=list&page={$page}&dir={$switch_dir}&sort=privs")).
		 td().
		 td().
		 hCell(href(gTxt('last_access'), "index.php?event=ign_user_mgmt&step=list&page={$page}&dir={$switch_dir}&sort=last_access"))
	 );

	 if ($rs) {
		 while ($a = nextRow($rs)) {
			 extract($a);
			 if ($name == $ign_user)
			 {
				 $deletelink = '';
			 } else {
				 $deletelink = dLink('ign_user_mgmt','ign_user_delete','user_id',$user_id);
			 }
			 $savelink = fInput("submit",'save',gTxt('save'),'smallerbox');
			 $emailhref = '<a href="mailto:'.$email.'">'.$email.'</a>';
			 $RealNameInput = fInput('text','RealName',$RealName,'edit');
			 $emailInput = fInput('text','email',$email,'edit');

			 $row[] = '<form action="index.php" method="post">';

			 $row[] = ($allow_edit)
				 ? td($RealNameInput)
				 : td($RealName);

			 $row[] = td($name);

			 $row[] = ($allow_edit)
				 ? td($emailInput)
				 : td($emailhref);

			 $row[] = ($allow_edit)
				 ? td(ign_privList($privs).popHelp("about_privileges"))
				 : td(ign_getPrivLevel($privs).popHelp("about_privileges"));

			 $row[] = ($allow_edit) ? td($savelink) : '';

			 $row[] = ($allow_edit)
				 ? hInput("user_id",$user_id). eInput("ign_user_mgmt").sInput('ign_userSave')
				 : td();

			 $row[] = '</form>';

			 $row[] = ($allow_edit)
				 ? td($deletelink,10)
				 : td();

			 //clean up last_access
			 if ($last_access == 0) $last_access = 'Never';
			 $row[] = td($last_access);

			 $out[] =
				 tr(join('',$row));
			 unset($row);
		 }

		 $out[] = endTable();
		 $out[] = nav_form('ign_user_mgmt', $page, $numPages, $sort, 'asc', '1', '1');

		 return join('',$out);
	 }
 }

// -------------------------------------------------------------
 function ign_user_delete()
 {
	 global $ign_user_db;
	 $user_id = ps('user_id');
	 $name = fetch('Realname',$ign_user_db,'user_id',$user_id);
	 if ($name) {
		 $rs = safe_delete($ign_user_db,"user_id = '$user_id'");
		 if ($rs) ign_admin(messenger('user',$name,'deleted'));
	 }
 }

// -------------------------------------------------------------
 function ign_new_user_form()
 {
	 $out = array(
		 hed(ign_gTxt('add_new_user'),3,' align="center" style="margin-top:2em"'),
		 graf(ign_gTxt('a_message_will_be_sent_with_login'), ' align="center"'),
		 startTable('edit'),
		 tr( fLabelCell( 'real_name' ) . fInputCell('RealName') ),
		 tr( fLabelCell( 'login_name' ) . fInputCell('name') ),
		 tr( fLabelCell( 'email' ) . fInputCell('email') ),
		 tr( fLabelCell( 'privileges' ) . td(ign_privList().popHelp('about_privileges')) ),
		 tr( td() . td( fInput( 'submit','',gTxt('save'),'publish').
			 popHelp('add_new_user')) ),
		 endTable(),
		 eInput('ign_user_mgmt').sInput('ign_userSaveNew'));

	 return form(join('',$out));
 }

// -------------------------------------------------------------
 function ign_generatePassword($length=10)
 {
	 $pass = "";
	 $chars = "023456789bcdfghjkmnpqrstvwxyz";
	 $i = 0;
	 while ($i < $length) {
		 $char = substr($chars, mt_rand(0, strlen($chars)-1), 1);
		 if (!strstr($pass, $char)) {
			 $pass .= $char;
			 $i++;
		 }
	 }
	 return $pass;
 }

// -------------------------------------------------------------
 function ignMail($to_address, $subject, $body, $reply_to = null, $from='')
 {
	 global $txp_user, $prefs, $ign_user_db;
	 if (isset($txp_user))
	 { // Likely sending passwords
		 extract(safe_row("RealName, email", "txp_users", "name = '$txp_user'"));
	 }
	 else
	 { // Likely sending comments -> "to" equals "from"
//		 extract(safe_row("RealName, email", $ign_user_db, "email = '$to_address'"));
		 $RealName = "Site Administrator";
		 $h = parse_url(hu);
		 $email = 'no-reply@'.$h['host'];
	 }

	 if ($prefs['override_emailcharset'])
	 {
		 $charset = 'ISO-8599-1';
		 if (is_callable('utf8_decode'))
		 {
			 $RealName = utf8_decode($RealName);
			 $subject	 = utf8_decode($subject);
			 $body				 = utf8_decode($body);
			 $to_address = utf8_decode($to_address);
			 if (!is_null($reply_to)) $reply_to = utf8_decode($reply_to);
		 }
	 } else {
		 $charset = 'UTF-8';
	 }

	 $RealName = strip_rn($RealName);
	 $subject = strip_rn($subject);
	 $email = strip_rn($email);
	 if (!is_null($reply_to)) $reply_to = strip_rn($reply_to);

	 if (!is_callable('mail'))
	 {
		 if (txpinterface == 'admin' && $GLOBALS['production_status'] != 'live')
			 echo tag(gTxt('warn_mail_unavailable'),'p',' style="color:red;" ');
		 return false;
	 }
	 else
	 {
		 return mail($to_address, $subject, $body,
			 "From: $RealName <$email>\r\n"
		 ."Reply-To: ". ((isset($reply_to)) ? $reply_to : "$RealName <$email>") . "\r\n"
		 ."X-Mailer: Textpattern\r\n"
		 ."Content-Transfer-Encoding: 8bit\r\n"
		 ."Content-Type: text/plain; charset=\"$charset\"\r\n");
	 }
 }

// -------------------------------------------------------------
 function ign_stopCache()
 {
	 global $ign_headerSent;

	 if (!$ign_headerSent)
	 {
		 header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
		 header('Cache-Control: no-store, no-cache, must-revalidate');
		 header('Cache-Control: post-check=0, pre-check=0', FALSE);
		 header('Pragma: no-cache');

		 $ign_headerSent = true;
	 }
 }

// -------------------------------------------------------------
 function ign_setCookie($acct, $time=false, $path='/')
 {
	 extract(lAtts(array(
		 'name' => '',
		 'realname' => '',
		 'last_access' => '',
		 'nonce' => '',
		 'privs' => '',
		 'email' => ''
		 ), $acct, 0)
	 );

	 if(empty($name))
	 {
		 return false;
	 }

	 $o[] = urlencode($name);
	 $o[] = urlencode($privs);
	 $o[] = urlencode($realname);
	 $o[] = urlencode(md5($name.$privs.$nonce));
	 $o[] = urlencode($last_access);
	 $o[] = urlencode($email);

	 $val = join(',', $o);

	 $d = explode('.', $_SERVER['HTTP_HOST']);
	 // $domain = '.'.join('.', array_slice($d, 1-count($d), count($d)-1));
	$domain = ign_getDomain();

	 setcookie('ign_login', $val, $time, $path, $domain);
	 $_COOKIE['ign_login'] = $val; //manually set value so cookie is available immediately

	 return true;
 }

// -------------------------------------------------------------
// This is a slight alteration for .co.uk like domains...
// Thanks to Gerhard Lazu for this code.

  function ign_getDomain() {
    $d = explode('.', $_SERVER['HTTP_HOST']);
    // $d_copy keeps code simple
    $d_copy = $d;
    // Make sure the last 2 values look like TLDs (no more than 3 characters). Not bulletproof (.info? .mobi?), but simple.
    if ( (count($d) > 2) && (strlen(array_pop($d_copy)) < 4) && (strlen(array_pop($d_copy)) < 4) ) {
      return join('.', array_slice($d, -3, 3));
    }
    else {
      return join('.', array_slice($d, -2, 2));
    }
  }

// -------------------------------------------------------------
 function ign_getCookie()
 {

	 $arr = explode(',', cs('ign_login'));
	 $n = count($arr);
	 for ($i = 0; $i < $n; $i++)
	 {
		 $arr[$i] = urldecode($arr[$i]);
	 }

	 return $arr;
 }

// -------------------------------------------------------------
 function ign_add_paging()
 {
	 //define functions new to 4.0.4 necessary for paging

	 if (!function_exists('pager'))
	 {
		 function pager($total, $limit, $page)
		 {
			 $num_pages = ceil($total / $limit);
			 $page = $page ? (int) $page : 1;
			 $page = min(max($page, 1), $num_pages);
			 $offset = max(($page - 1) * $limit, 0);
			 return array($page, $offset, $num_pages);
		 }
	 }

	 if (!function_exists('nav_form'))
	 {
		 function nav_form($event, $page, $numPages, $sort, $dir, $crit, $search_method)
		 {
			 if ($numPages > 1)
			 {
				 $option_list = array();

				 for ($i = 1; $i <= $numPages; $i++)
				 {
					 if ($i == $page)
					 {
						 $option_list[] = '<option value="'.$i.'" selected="selected">'."$i/$numPages".'</option>';
					 }

					 else
					 {
						 $option_list[] = '<option value="'.$i.'">'."$i/$numPages".'</option>';
					 }
				 }

				 $nav = array();

				 $nav[] = ($page > 1) ?
					 PrevNextLink($event, $page - 1, gTxt('prev'), 'prev', $sort, $dir, $crit, $search_method).sp :
					 tag('&#8249; '.gTxt('prev'), 'span', ' class="navlink-disabled"').sp;

				 $nav[] = '<select name="page" class="list" onchange="submit(this.form);">';
				 $nav[] = n.join(n, $option_list);
				 $nav[] = n.'</select>';
				 $nav[] = '<noscript> <input type="submit" value="'.gTxt('go').'" class="smallerbox" /></noscript>';

				 $nav[] = ($page != $numPages) ?
					 sp.PrevNextLink($event, $page + 1, gTxt('next'), 'next', $sort, $dir, $crit, $search_method) :
					 sp.tag(gTxt('next').' &#8250;', 'span', ' class="navlink-disabled"');

				 return '<div style="text-align: center; margin-top: 1em;"><form class="prev-next" method="get" action="index.php">'.
					 n.eInput($event).
					 ( $sort ? n.hInput('sort', $sort).n.hInput('dir', $dir) : '' ).
					 ( $crit ? n.hInput('crit', $crit).n.hInput('search_method', $search_method) : '' ).
					 join('', $nav).
					 '</form></div>';
			 }

			 else
			 {
				 return '<div style="text-align: center; margin-top: 1em;">'.graf($page.'/'.$numPages, ' class="prev-next"').'</div>';
			 }
		 }
	 }
 }


// -------------------------------------------------------------
 function ign_user_field($atts)
 {
	 extract(lAtts(
		 array(
			 'name' => 'p_userid',
			 'value' => '',
			 'class' => '',
			 'title' => '',
			 'onClick' => '',
			 'size' => '',
			 'tab' => '',
			 'id' => ''
		 ), $atts, 0)
	 );

	 return fInput('text',$name, $value, $class, $title, $onClick, $size, $tab, $id );
 }

// -------------------------------------------------------------
 function ign_pass_field($atts)
 {
	 extract(lAtts(
		 array(
			 'name' => 'p_password',
			 'value' => '',
			 'class' => '',
			 'title' => '',
			 'onClick' => '',
			 'size' => '',
			 'tab' => '',
			 'id' => ''
		 ), $atts, 0)
	 );

	 return fInput('password', $name, $value, $class, $title, $onClick, $size, $tab, $id);
 }

// -------------------------------------------------------------
 function ign_submit_field($atts)
 {
	 extract(lAtts(
		 array(
			 'name' => 'submit',
			 'value' => '',
			 'class' => ''
		 ), $atts, 0)
	 );

	 return fInput('submit', $name, $value, $class);
 }
// -------------------------------------------------------------
 function ign_hidden_field($atts)
 {
	 extract(lAtts(
		 array(
			 'value' => 'Login',
			 'class' => ''
		 ), $atts, 0)
	 );

	 return fInput('submit','', $value, $class);
 }

// -------------------------------------------------------------
 function ign_checkbox($atts)
 {
	 extract(lAtts(
		 array(
			 'name' => 'remember',
			 'value' => '1',
			 'checked' => '',
			 'tab' => '',
			 'id' => '',
		 ), $atts, 0)
	 );

	 return checkbox($name, $value, $checked, $tab, $id);
 }

// -------------------------------------------------------------
 function ign_error_msg($atts, $thing='')
 {
	 global $ign_err, $ign_error_codes;

	 $text = (!empty($thing)) ? $thing : IGN_LOGIN_ERR;

	 extract(lAtts(
		 array(
			 'error' => ''
		 ), $atts, 0)
	 );

	 if(!empty($error)) //match to error
	 {

		 $retVal = ($ign_error_codes(strtolower($error)) == $ign_err) ? parse($text) : '';

	 } elseif($ign_err > 1) {
		 $retVal = parse($text);
	 } else {
		 $retVal = '';
	 }

	 return $retVal;
 }

// -------------------------------------------------------------
 function ign_user_info ( $atts )
 {
	 extract(lAtts(
		 array(
			 'type' => 'name',
			 'format' => 'H:i T n-j-y'
		 ), $atts, 0)
	 );

	 list($types['name'],,$types['realname'],,$types['last_access'], $types['email']) = ign_getCookie();

	 if($type == 'last_access')
	 {
		 $types['last_access'] = date($format, strtotime($types['last_access']));
	 }

	 return (!empty($types[$type])) ? $types[$type] : '';
 }

// -------------------------------------------------------------
 function ign_logout_link($atts, $thing)
 {
	 global $ign_user;
	 if(empty($ign_user)) return ""; //exit if user not logged in

	 extract(lAtts(array(
			 'class' => '',
			 'onclick' => '',
			 'alt' => 'Logout',
			 'title' => 'Logout',
			 'return_path' => '',
			 'id' => '',
			 'linktext' => ''
		 ), $atts, 0)
	 );

	 if(!empty($return_path)) list($return_path) = explode('?', $_SERVER['REQUEST_URI']);

	 $text = (!empty($thing)) ? $thing : ((!empty($linktext)) ? $linktext : IGN_LOGOUT_LINK);

	$q = (!empty($_SERVER['QUERY_STRING'])) ? $_SERVER['QUERY_STRING']."&logout=1" : 'logout=1';

	 $o[] = "<a href='{$return_path}?$q'";
	 $o[] = (!empty($class)) ? "class='$class'" : '';
	 $o[] = (!empty($alt)) ? "alt='$alt'" : '';
	 $o[] = (!empty($title)) ? "title='$title'" : '';
	 $o[] = (!empty($id)) ? "id='$id'" : '';
	 $o[] = (!empty($onclick)) ? "onclick='$onclick'" : '';
	 $o[] = ">$text</a>";

	 return join($o);
 }

// -------------------------------------------------------------
 function ign_default_form($form)
 {
	 global $ign_err;
	 // TODO: add error display options

	 //function for default forms
	 switch ($form)
	 {
		 case 'login':
			 $retVal = <<<login
<div class='login'>
 <p><span class='error'><txp:ign_error_msg >There was a problem logging in.</txp:ign_error_msg></span></p>
 <p><label>Name:<br />
	 <txp:ign_user_field />
 </label><br />
 <label>Password:<br />
	 <txp:ign_pass_field />
 </label><br />
 <label>Remember Me? <txp:ign_checkbox name='stay' value='1' /></label>
 <txp:ign_submit_field name='login' value='Login'/></p>
</div>
login;
			 break;

		 case 'self_edit':
			 $retVal = <<<edit
<div class='selfedit'>
 <label>New Password:<br />
	 <txp:ign_pass_field name='new_pass' />
 </label><br />
 <label>Confirm Password:<br />
	 <txp:ign_pass_field name='confirm_pass' />
 </label>
 <label>Email New Password?<br />
	 <txp:ign_checkbox name='email_pass' value='1' />
 </label><br />
 <txp:ign_submit_field name='update' value='Update Password' />
</div>
edit;
			 break;

		 case 'current_user':
			 $retVal = <<<current
<div class='active'>
 <p><txp:ign_user_info type="realname" /><br />
 <txp:ign_logout_link>Log out</txp:ign_logout_link></p>
</div>
current;
			 break;

	 }

	 return $retVal;
 }


//deprecated tags
//-----------------------------------------------
 function ign_usr_online($atts, $thing='') //deprecated, use ign_active_users instead
 {
	 return ign_active_users($atts,$thing);
 }

//-----------------------------------------------
 function ign_logged_user($atts)
 {
	 return ign_current_user($atts);
 }


# --- END PLUGIN CODE ---

// CHANGED: 2008.04.05 - fixed logout link under messy URLs
// CHANGED: 2006.12.15 - removed set msg routine
// CHANGED: 2006.12.15 - added ign_setCookie, ign_getCookie to consolidate cookie routines
// CHANGED: 2006.12.15 - added email, last_access to cookie for use in ign_user_info
// CHANGED: 2006.12.15 - cookies now blanket for root domain, not subdomain.
// FIXME: add toggle for root vs non-root cookies?
// TODO: improve localization
// TODO: revise UI Permissions model (allow non-admins to see elements of the UI)
// TODO: Implement Edit Password Feature
// TODO: Password Protect File Downloads?
// TODO: Protect RSS Feeds?
// TODO: Redirect on login - allow users to be redirected to a specific section on login
// TODO: Move tag output to TXP forms
// TODO: Adjust length of time user is tracked as ONLINE
// TODO: Url encode / decode cookie string

if (0) {
?>
# --- BEGIN PLUGIN HELP ---

h1. Basic usage:

As of version 0.5, this plugin uses forms for the following tags:
@<txp:ign_show_login>@ (and @<txp:ign_password_protect>@ which calls show_login).
@<txp:ign_current_user />@ (which replaces the poorly named @<txp:ign_logged_user>@, though that format is also still supported)

See "Form Elements":#form_elements and "Form Examples":#examples below for more information on constructing these forms.

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_if_logged_in>[<txp:else />]</txp:else></txp:ign_if_logged_in>@

Use to control display of content depending on login state.
Supports use of @<txp:else />@
Note that @<txp:ign_if_logged_in></txp:ign_if_logged_in>@ tags cannot be nested within other @<txp:ign_if_logged_in>@ blocks due to the way that the TXP engine parses tags.
More discussion on this point can be found in "this discussion":http://forum.textpattern.com/viewtopic.php?id=10375 in the Textpattern forums.

Accepted parameters
|*privs*|comma separated list of privilege levels to compare against. If omitted, any valid user will have access.|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_password_protect></txp:ign_password_protect>@

Use to password protect part or all of a txp website against users in the txp_user database (on the site_admin tab).
Can be used in page or form templates, or even directly within an article.
Note that use of this tag is deprecated. Use @<txp:ign_show_login>@ and @<txp:if_logged_in>@ for more flexibility.

Attributes:
table{background-color:#cc9;}.
|*privs*|Comma separated list of privilege levels to compare against.<br />If omitted, plugin simply checks for account existence (including privs = None).|
|*form*|The name of a TXP form to use to render the login form. Defaults to "login_form"; if form doesn't exist or no form is found, renders a generic form.|
|-*err_msg*-|-Sets error message on bad logins- _Deprecated_|
|-*login_msg*-|-Sets the greeting message that is displayed above the form- _Deprecated_|
|-*class*-|-Sets the class assigned to the div containing the form. Default value is ign_login- _Deprecated_|
|-*remember*-|-Boolean to display checkbox for "remember me".<br />Set to 1 or true to display check box (and set persistent cookie)<br />Set to 0 or false to disallow.<br />Default is off.- _Deprecated_|
|-*login_type*-|-Option to control how login is requested.<br />Set to "page" to use browser's authentication dialog.<br />Omit or set to anything else to use inline form element.<br />Default is inline.-|
|-*hide_login*-|-Set to true to not display login form at location of protected content when not logged in- _Deprecated_|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_current_user />@

Displays logged in user name with link to log out if logged in. Replaces the old tag @<txp:ign_logged_user>@, though the older form is an alias for @<txp:ign_current_user>@

Attributes:

table{background-color:#cc9;}.
|*form*|The name of a TXP form to use to render the login form. Defaults to "current_user"; if form doesn't exist or no form is found, renders a generic form.|
|*logged_msg*|Replaces default "not logged in" message.|
|*display*|Options are 'name' or 'realname'; 'name' will display the login name, 'realname' will display the real name as
entered.<br />Defaults to 'name'<br />|
|*verbose*|Set to true (or 1) to include logged_msg text, set to false (0) to display only username.<br />Defaults to false.|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_show_login />@

Displays login form independent of protected area. As of version 0.5 - show login uses txp forms to render.

Attributes:

table{background-color:#cc9;}.
|*form*|The name of a TXP form to use to render the login form. Defaults to "login_form"; if form doesn't exist or no form is found, renders a generic form.|
|*show_logged*|Boolean to display "logged-in as" message w/ logout link when user is logged in<br />Set to 1 or true to show, 0 or false to hide.<br />Default is on.|
|-*logged_msg*-|-Sets the message displayed when not logged in- _Deprecated_|
|-*login_msg*-| -Sets the greeting message that is displayed above the form- _Deprecated_|
|-*remember*-| -Boolean to display checkbox for "remember me"<br />Set to 1 or true to display check box (and set persistent cookie) set to 0 or false to disallow.<br />Default is off.- _Deprecated_|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_usr_online>@

Displays list of currently logged on users. Can be used as a self-closing tag - i.e. @<txp:ign_usr_online />@ -
or as matching tags - @<txp:ign_usr_online>Content</txp:ign_usr_online>@. If used as matched pairs, any content
included between the tags will only be diplayed if there are user names to display.

Attributes:

table{background-color:#cc9;}.
|*privs*|accepts comma-delimited list to constrain list to users of specific privilege levels.<br />If omitted, all users are listed.|
|*display*|Options are 'name' or 'realname'; 'name' will display the login name, 'realname' will display the real name as
entered.<br />Defaults to 'name'|
|*wraptag*|(self-explanatory)|
|*break*|(self-explanatory)|
|*class*|(self-explanatory)|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_self_edit>@

Displays a form to registered users to allow them to reset their password. Does not display anything if user is not logged in.

Attributes:

table{background-color:#cc9;}.
|*class*|
|*id*|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_if_logged_in><txp:else /></txp:ign_if_logged_in>@

Conditional to display different content depending on whether the user is logged in or not.

Attributes:

table{background-color:#cc9;}.
|*privs*|Comma separated list of privilege levels to compare against.<br />If omitted, plugin simply checks for account existence (including privs = None).|

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_if_not_logged_in></txp:ign_if_not_logged_in>@

Displays content _only_ if user *not* logged in.

Attributes:

No longer accepts privs attribute. not_logged_in only does an absolute check if user is logged in. If you want to check for privileges, use if logged in and the else clause instead.

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_page_privs />@

Use at top of page/element to set element-wide privilege levels (can be overridden at the tag level)

h3{color:#cc9}. <a name="form_elements"></a>FORM ELEMENTS

The following tags are primarily intended for use in forms (though I suspect inventive users will find clever uses well beyond their original intended use...)

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_user_field />@

Used to render HTML textfield for username input.

Attributes:

table{background-color:#cc9;}.
|*name*||
|*value*||
|*class*||
|*title*||
|*onclick*||
|*size*||
|*tab*||
|*id*||

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_pass_field />@

Used to render HTML password textfield.

Attributes:

Same as @<txp:ign_user_field />@

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_hidden_field />@

Hidden form element

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_submit_field />@

Form element

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_checkbox />@

Form element

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_error_msg></txp:ign_error_msg>@

Used to specify error messages. Will return the value contained between the tags, or the IGN_LOGIN_ERROR constant if self-closing / empty.

Attributes:

table{background-color:#cc9;}.
|*error*|can be used to designate a specific error condition to match|

Accepted values for error attribute:

table{background-color:#cc9;}.
|success|
|logout|
|auth|
|cookie|
|privs|


h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_user_info />@

Return user details in plain text

Attributes:

table{background-color:#cc9;}.
|*type*|the type of data to return, accepted values are name, realname, last_access, email|
|*format*|used to format the last_access parameter, uses PHP's "date format strings":http://www.php.net/date |

h4{color:#900;border-bottom:1px dotted #999;border-top:1px dotted #999;background-color:#ddd;}. @<txp:ign_logout_link>[_logout link_]</txp:ign_logout_link>@

Used to create a logout link. Use either in self-closing format or as a container tag. If used as a container, text between the open and close tags will be used as the link. In self-closing form, you may supply a "linktext" attribute for the text, otherwise the value of IGN_LOGOUT_LINK constant will be used.

Examples:
@<txp:ign_logout_link>Logout Container-style</txp:ign_logout_link>@
@<txp:ign_logout_link linktext="Logout Attribute-style" />@
@<txp:ign_logout_link />@

table{background-color:#cc9;}.
|*return_path*|Used if you wish to return to an alternate page than the current page on logout|
|*linktext*|Used to denote the text of the logout link in self-closing format; ignored if there is text present between opening and closing tags|
|*class*|Self-explanatory|
|*id*|Self-explanatory|
|*alt*|Self-explanatory|
|*title*|Self-explanatory|
|*onclick*|Self-explanatory|

<a name="examples"></a>

h3{color:#cc9}. FORM Examples

These are the default forms, as generated by the plugin, but should give you enough to get started:

h4. Login form

bc.	<div class='login'>
	 <p><span class='error'><txp:ign_error_msg >There was a problem logging in.</txp:ign_error_msg></span></p>
	 <p><label>Name:<br />
		 <txp:ign_user_field />
	 </label><br />
	 <label>Password:<br />
		 <txp:ign_pass_field />
	 </label><br />
	 <label>Remember Me? <txp:ign_checkbox name='stay' value='1' /></label>
	 <txp:ign_submit_field name='login' value='Login'/></p>
	</div>

h4.

Changelog:

* _0.5b9_ - 2008.4.6
** addressed issue with log *in* links with messy urls

* _0.5b8_ - 2008.4.5
** addressed issue with logout links with messy urls

* _0.5b7_ - 2008.3.18
** yet another interim release, adds in Gerhard Lazu's fix for multiple tld domains, fixes form issues with self-edit, stubs for file download protection.

* _0.5b6_ - 2007.5.21
** interim release with support for user level administrative permissions on ign_user database

* _0.5b5_ - 2007.3.20

* _0.5b4_ - 2007.2.20

* _0.5b3_ - 2007.1.24
** fix for caching issue (now non-protected pages will force re-validation, protected pages send no-cache headers)
** improved ign_logout_link tag behaviour to prevent output of empty links
* _0.5b2_ - 2007.1.18
** removed debugging code 'woo hoo', added hooks to ddh_vanilla_integration
* _0.5b_ - 2007.1.10
* _0.4.5_ - 2006.12.18
** pagination + sorting of user list when using alternate user database (Thanks to Jan Tittelbach / permanent for sponsoring this addition!)
** moved Login form, Error messages to TXP forms for easier customization / localization
* _0.4.3_ - _2006-5-30_
** restored name display in ign_logged_user (broken in 0.4.2d - sorry!)
* _0.4.2d_ - _2006-5-5_
** fixed bug with "Use custom DB" radio button on usr_management screen
* _0.4.2c_ - _2006-3-22_
** updated create table routine to set character set on ign_users
** updated authentication routine to allow underscores in user names
** corrected problem displaying form when toggling between txp_users and ign_users in admin interface
* _0.4.2b_ - _2006-3-21_
** bug fix for login_msg when using ign_password_protect to display login
* _0.4.2a_
** testing release for cache control
** added ign_stopCache() function to send headers, called in ign_checkPrivs()
==

# --- END PLUGIN HELP ---
<?php
}

?>
