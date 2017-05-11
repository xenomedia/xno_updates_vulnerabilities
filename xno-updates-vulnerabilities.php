#!/usr/bin/env php
<?php
/**
 * This script checks for core, plugin, themes updates and vulnerabilties.
 *
 * Vulnerabilities are check agains https://wpvulndb.com/ and Change log in
 * Wordpress plugin.
 *
 * This script forces the checks, does not depend on the wp_cron.
 *
 * To properly functions user the following env vars :
 *    XCHANNELS - a valid json string that holds the slack channels to send
 *				  notifications.
 *				  info channel(s) -  will be user to send any information.
 *				  fire channel(s) -  will be user to send any vulnerability.
 *
 *				  Example:
 *    					export XCHANNELS='{"info":["notification-channel"],"fire":["emergency-channel"]}'
 *
 *    XNOTIFY_USERS - A valid json string that will hold slack user id's slack of
 *				users that need to be notified.
 *
 *				Example:
 *					export XNOTIFY='{"info":["user1"],"fire":["user1","user2"]}'
 *
 * 	  XSLACK - Webhook **FULL** URL. Only uses one webhook to send to different channels.
 *
 *				Example:
 *					export XSLACK='https://hooks.slack.com/services/XXXX/XXXX/XXXX'
 *
 * 	  XJIRA - Jira: jenkins Build id, project, labels and host.
 *			  if not progress_transision_id set then default will be 4.
 *
 *				Example:
 *					export XJIRA='{"project":"XXX",\
 * 					"labels":["WORDPRESS","PLUGINS","UPDATE"],\
 * 					"server":"http://myjira.com",
 *					"progress_transition_id":"4"
 * 					"user":"XXX"
 * 					"pwd":"XXX"
 *					"assignee":"admin"}'
 *
 *    XTOKEN -  An md5 encripted string of the wp prefix to verify that we can safetly run this script.
 *
 *				Example:
 *					export XTOKEN=`echo -n "wp_prefix_" | openssl md5 | sed 's/^.* //'`
 *
 *
 * The program will load the wp site environment.
 *
 * @author caromanel <carolina@xenomedia.com>
 * @package wp-updates-and-vulnerabilities.
 */

// Only command line please.
if ( php_sapi_name() !== 'cli' ) {
	exit( '<h3>Go away!!<h3>' );
}

// Location of wp-load.php so we have access to database and $wpdb .
$wp_load_loc = 'wp-load.php';

// Loads WP environment.
require_once( $wp_load_loc );

// If not a WP site then abort.
if ( ! defined( 'ABSPATH' ) ) {
	exit( 'Not authorize, not a valid wp instance!' );
}

// If not a valid token abort to avoid execution in a wrong environment.
global $wpdb;
$token = getenv( 'XTOKEN', true ) ? : false;

if (  md5( $wpdb->prefix ) !== $token ) {
	exit( 'Not authorize, not a valid token!' );
}

// Inits mail class.
new XNO_Updates_Vulnerabilities();

/**
 * Verify wordpress updates and check for vulnerabilities
 */
class XNO_Updates_Vulnerabilities {
	/**
	 * Holds wpvulndb API url
	 *
	 * @var    string
	 * @since   1.0.0
	 */
	private $wpvulndb_url;

	/**
	 * Holds object of class slack with slack webhook information.
	 *
	 * @var    array
	 * @since   1.0.0
	 */
	private $slack;

	/**
	 * Holds object of class Jira.
	 *
	 * @var    array
	 * @since   1.0.0
	 */
	private $jira;

	/**
	 * Holds Jira message.
	 *
	 * @var    array
	 * @since   1.0.0
	 */
	private $jira_body = '';

	/**
	 * Holds a flag to see if site is vulnerable.
	 *
	 * @var    array
	 * @since   1.0.0
	 */
	private $site_is_vulnerable = false;

	/**
	 * Constructor
	 *
	 * Set class variables.
	 */
	public function __construct() {

		// Comunnicates with Slack
		$this->slack = new XNO_Slack();

		// Commmunicates with Jira.
		$this->jira = new XNO_Jira();

		$this->init();

		// Calls core check.
		$this->check_core();

		// Calls plugins check.
		$this->check_plugins( $plugins_active_only );

		// Calls themes check.
		$this->check_themes( $themes_active_only );

		$this->jira->open_task( $this->site_is_vulnerable );
	}

	/**
	 * Sets default setting for class.
	 *
	 * @param void
	 * @return void
	 */
	private function init() {
		// Wpvulndb API site to check for vulnerabilities.
		$this->wpvulndb_url = array(
			'core' 	  => 'https://wpvulndb.com/api/v2/wordpresses/',
			'plugins' => 'https://wpvulndb.com/api/v2/plugins/',
			'themes' => 'https://wpvulndb.com/api/v2/themes/',
		);

		// Check for active plugins only?, default yes.
		$plugins_active_only = getenv( 'XPLUGINS_ACTIVE', true ) ? : false;

		// Check for active theme only?, default yes.
		$themes_active_only = getenv( 'XTHEMES_ACTIVE', true ) ? : false;
	}

	/**
	 * Defines the function used to call the cURL library.
	 *
	 * @param string $url  To URL to which the request is being made.
	 * @return string $response  The response, if available; otherwise, null.
	 */
	private function curl( $url ) {
		$response = false;

		// Checks if url entry is set.
		if ( empty( $url ) ) {
			return false;
		}

		// 1. Tries to use wp_remote_get.
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			echo esc_attr( $response );
		}

		// If the response is an array, it's coming from wp_remote_get.
		if ( is_array( $response ) ) {
			$response = $response['body'];
		}

		echo "\n" . $response;

		return $response;
	}

	/**
	 * Look up for strings that are considered as vulnerabilities in plugin description.
	 *
	 * @param string $description	The plugin updates description.
	 * @return boolean $found	The response from the URL; null if empty.
	 */
	private function check_in_description( $description ) {
		$array = array(
			'Vulnerability',
			'SQL Injection',
			'Cross-Site',
			'CSRF',
			'XSS',
			'Unvalidated Redirects',
			'Inject',
			'Insecure',
			'Unvalidated Input',
			'Malicious',
			'Risk',
			'Hack',
			'Hijacking',
		);

		$string = strtolower( $description );

		$found = false;

		// Loops in array of words to see if they exists in the plugin update descipriont.
		foreach ( $array as $words => $word ) {

			if ( false !== strpos( $string, strtolower( $word ) ) ) {
				$found = true;
				break;
			}
		}

		return $found;
	}

	/**
	 * Calls wpvulndb API o check for vulnerabilities in its db.
	 *
	 * @param string $url 	The URL of the core/plugin/theme in wpvulndb.
	 * @param string $ver 	slug of the core/plugin/theme in wpvulndb.
	 * @return boolean $vulnerable if found in wpvulndb api db.
	 */
	private function check_with_wpvulndb( $url = null, $ver = null ) {

		// cURL call.
		$response = $this->curl( $url );

		if ( empty( $response ) ) {
			return 'Unkown';
		}

		$json = json_decode( $response );

		$vulnerable = false;

		// Loops in API response to check for vulnerabilities reported.
		foreach ( $json as $vul => $key ) {
			$count = count( $key->vulnerabilities );
			$i = 1;
			foreach ( $key->vulnerabilities as $v ) {
				if ( $v->fixed_in >= $ver ) {
					$i++;
				}
			}

			$vulnerable = ( $i < $count );
		}

		return $vulnerable;
	}

	/**
	 * Checks to see if any WP core updates.
	 *
	 * @return bool if there are core updates.
	 */
	public function check_core() {
		global $wp_version;

		// Forces WP to check its core for updates.
		do_action( 'wp_version_check' );

		// Get information of core update.
		$update_core = get_site_transient( 'update_core' );

		if ( 'upgrade' === $update_core->updates[0]->response ) {

			// Some plugins maybe hidding core version, so let's check it in version.php.
			require_once( ABSPATH . WPINC . '/version.php' );

			// Gets the new WP core version.
			$new_core_ver = $update_core->updates[0]->current;

			// Holds current wp version as int number.
			$ver_int = filter_var( $wp_version, FILTER_SANITIZE_NUMBER_INT, $wp_version );

			// Checks for vulnerabilties reported in wpvulndb.
			$vulnerable = $this->check_with_wpvulndb( $this->wpvulndb_url['core'] . $ver_int );

			$fields = array();

			if ( true === $vulnerable ) {
				array_push( $fields, [
					'title' => sprintf( 'Reference' ),
					'value' => sprintf( '%1$s%2$s', $this->wpvulndb_url['core'], $ver_int ),
					'short' => true,
				]);

			} else {
				array_push( $fields, [
						'title' => sprintf( 'Current Version' ),
						'value' => $wp_version,
						'short' => true,
					],
					[
						'title' => sprintf( 'To' ),
						'value' => $new_core_ver,
						'short' => true,
					]
				);
			}

			$slack = [
				'vulnerable' => $vulnerable,
				'the_message' => sprintf( 'WP Core %s is OUT OF DATE', $wp_version ),
				'pretext' => sprintf( 'Please update from:' ),
				'fields' => $fields,
			];

			// Marks the site as vulnerable.
			$this->site_is_vulnerable = $vulnerable;

			$description = sprintf( 'WP Core:  From %1$s -- To -- %2$s', $plugin_info['Version'], $data->new_version );

			echo sprintf( "\n%s", $description );

			// Makes Jira body.
			$this->jira->set_description( $description );

			// Calls Slack boot to notify everything is up to date.
			$this->slack->talk( $slack );

			return true;

		} else {

			$slack = [
				'vulnerable' => false,
				'the_message' => sprintf( 'WP Core %s is up-to-date.', $wp_version ),
				'pretext' => '',
			];

			echo sprintf( "\nWP Core is up-to-date." );

			// Calls Slack boot to notify everything is up to date.
			$this->slack->talk( $slack );
		}

		return false;
	}

	/**
	 * Check to see if any plugin updates.
	 *
	 * @param boolean $active_only  checks if only look for active plugins updates.
	 * @return boolean
	 */
	public function check_plugins( $active_only = false ) {

		// Force WP to check plugins for updates.
		do_action( 'wp_update_plugins' );

		// Get information of updates.
		$update_plugins = get_site_transient( 'update_plugins' );

		if ( ! empty( $update_plugins->response ) ) {

			// Gets plugins that need updating.
			$plugins_need_update = $update_plugins->response;

			// Active plugins equals 2.
			if ( true === $active_only ) {

				// Gets active plugins.
				$active_plugins = array_flip( get_option( 'active_plugins' ) );

				// Intersect to keep only actives.
				$plugins_need_update = array_intersect_key( $plugins_need_update, $active_plugins );
			}

			if ( count( $plugins_need_update ) >= 1 ) {

				// Required for plugin API.
				require_once( ABSPATH . 'wp-admin/includes/plugin-install.php' );
				// Required for WP core version.
				require_once( ABSPATH . WPINC . '/version.php' );

				$fields = array();

				array_push( $fields, [
					'title' => sprintf( 'Plugin' ),
					'value' => '',
					'short' => true,
				]);

				array_push( $fields, [
					'title' => sprintf( 'To' ),
					'value' => '',
					'short' => true,
				]);

				$plugins_vul = 0;

				// Verifies if there are vulnerabilities in wpvulndb API or in plugin update notify.
				foreach ( $plugins_need_update as $key => $data ) {

					$plugin_info = get_plugin_data( WP_PLUGIN_DIR . '/' . $key );

					$info = plugins_api( 'plugin_information', array( 'slug' => $data->slug ) );

					$wpvulndb_vul = $changelog_vul = array();

					$this_plugin_critical = '';

					if ( true === $this->check_with_wpvulndb( $this->wpvulndb_url['plugins'] . $data->slug ) ) {

						$wpvulndb_vul = [
							'value' => sprintf( 'Found in <%1%s%2%s|Wpvulndb>', $this->wpvulndb_url['plugins'], $data->slug ),
							'short' => true,
						];
					}

					if ( true === $this->check_in_description( $data->upgrade_notice ) ) {

						$changelog_vul = [
							'value' => sprintf( 'Found in <%schangelog/|Changelog>', $data->url ),
							'short' => true,
						];

					}

					$compat = 'Unknown';
					if ( isset( $info->tested ) && version_compare( $info->tested, $wp_version, '>=' ) ) {
						$compat = ''; // 100 % compatible
					} elseif ( isset( $info->compatibility[ $wp_version ][ $data->new_version ] ) ) {

						$compat = $info->compatibility[ $wp_version ][ $data->new_version ];
						$compat = sprintf( ' %1$d%% (%2$d "works" votes out of %3$d total)', $compat[0], $compat[2], $compat[1] );
					}

					$emotico = ':warning:';
					if ( count( $wpvulndb_vul ) || count( $changelog_vul ) ) {

						$plugins_vul++; // how many plugins have vulnerabilities.

						$this_plugin_critical = 'CRITICAL!'; //is this plugin vulnerable?

						$emotico = ':bangbang:';

					}

					array_push( $fields, [
						'value' => sprintf( '%1$s %2$s %3$s', $emotico, $plugin_info['Name'], $data->new_version ),
						'short' => true,
					]);

					array_push( $fields, [
						'value' => sprintf( '%1$s %2$s %3$s', $plugin_info['Version'], $compat, $this_plugin_critical ),
						'short' => true,
					]);

					if ( ! empty( $wpvulndb_vul ) ) {
						array_push( $fields, $wpvulndb_vul );
					}
					if ( ! empty( $changelog_vul ) ) {
						array_push( $fields, $changelog_vul );
					}

					$description = sprintf( 'Plugin:   %1$s -- From %2$s  -- To -- %3$s %4$s', $data->slug, $plugin_info['Version'], $data->new_version, $this_plugin_critical );

					echo sprintf( "\n%s", $description );

					// Makes Jira body.
					$this->jira->set_description( $description );

				}

				// Buils message based on the vulnerability of the plugin.
				if ( 1 === $plugins_vul ) {
					$mess = sprintf( 'There is a plugin with an available and CRITICAL update' );
				} elseif ( $plugins_vul > 1 ) {
					$mess = sprintf( '%d plugins have available and CRITICAL updates', $plugins_vul );
				} else {
					$plural = count( $plugins_need_update ) > 1 ? 's' : '';
					$has = count( $plugins_need_update ) > 1 ? 'have' : 'has';
					$mess = sprintf( '%1d plugin%2$s %3$s an available update%4$s', count( $plugins_need_update ),$plural, $has, $plural );
				}

				$slack = [
					'vulnerable' => ( $plugins_vul >= 1 ),
					'the_message' => $mess,
					'pretext' => sprintf( 'Please update from:' ) . "\n",
					'fields' => $fields,
				];

				$this->slack->talk( $slack );

				// Marks site as vulberable.
				$this->site_is_vulnerable = $slack['vulnerable'];

				return true;
			} // count

		} else {

			// Slack call to notify everything is up to date.
			$slack = [
				'vulnerable' => false,
				'the_message' => sprintf( 'Plugins up-to-date.' ),
			];

			echo sprintf( "\nPlugins are up-to-date" );

			$this->slack->talk( $slack );

		}

		return false;
	}

	/**
	 * Check to see if any theme updates.
	 *
	 * @param boolean $active_only - To check for theme active only.
	 * @return boolean return.
	 */
	public function check_themes( $active_only = false ) {

		// Forces WP to check for theme updates.
		do_action( 'wp_update_themes' );

		// Gets information of updates.
		$update_themes = get_site_transient( 'update_themes' );

		$current_theme = get_option( 'template' );

		if ( ! empty( $update_themes->response ) ) {

			// Themes that need updating.
			$themes_need_update = $update_themes->response;

			// Active themes equals 2.
			if ( true === $active_only ) {

				// find current theme that is active.
				$active_theme = array( $current_theme => array() );

				// only keep theme that is active.
				$themes_need_update = array_intersect_key( $themes_need_update, $active_theme );
			}

			if ( count( $themes_need_update ) >= 1 ) {

				$themes_vul = false;
				$fields = array();

				array_push( $fields, [
					'title' => 'Theme',
					'value' => '',
					'short' => true,
				]);

				array_push( $fields, [
					'title' => 'To',
					'value' => '',
					'short' => true,
				]);

				// Checks for vulnerabilities in wpvulndb.
				foreach ( $themes_need_update as $key => $data ) {

					$theme_info = wp_get_theme( $key );

					$wpvulndb_vul = '';
					if ( true === $this->check_with_wpvulndb( $this->wpvulndb_url['themes'],  $data->slug ) ) {
						$themes_vul = array(
							[
								'value' => $this->wpvulndb_url['themes'] . $data->slug,
								'short' => false,
							],
						);

						$plugins_vul++;
					}

					$current = ( $current_theme === $theme_info['Name'] ) ? ' (Current)' : '';

					array_push( $fields, [
						'value' => sprintf( '** %1$s %2$s', $theme_info['Name'], $data['Version'] ),
						'short' => true,
					]);

					array_push( $fields, [
						'value' => sprintf( '%1$s %2$s', $data['new_version'], $current ),
						'short' => true,
					]);

					$description = sprintf( 'Theme:   %1$s -- From %2$s -- To -- %3$s %4$s', $theme_info['Name'], $current, $data['new_version'] );

					echo sprintf( "\n%s", $description );

					// Makes Jira body.
					$this->jira->set_description( $description );

				}

				// Builds message based on theme vulnerability.
				if ( 1 === $themes_vul ) {
					$mess = sprintf( 'The following themes has an update available one is CRITICAL!' );
				} elseif ( $themes_vul > 1 ) {
					$mess = sprintf( '%d themes updates available, CRITICAL!', $plugins_vul );
				} else {
					$plural = count( $themes_need_update ) > 1 ? 's' : '';
					$has = count( $themes_need_update ) > 1 ? 'have' : 'has';
					$mess = sprintf( '%1$d themes%2$s %3$s available update%4$s', count( $themes_need_update ), $plural, $has, $plural );
				}

				$slack = [
					'vulnerable' => ( $themes_vul >= 1 ),
					'the_message' => $mess,
					'pretext' => sprintf( 'Please update from:' ) . "\n",
					'fields' => $fields,
				];

				$this->slack->talk( $slack );

				// Marks site as vulnerable
				$this->site_is_vulnerable = $slack['vulnerable'];

				return true;

			}
		}

			// Slack call to notify everything is up to date.
		$slack = [
			'vulnerable' => false,
			'the_message' => sprintf( 'Themes are up-to-update.' ),
		];

		echo sprintf( "\nThemes are up-to-update" );

		$this->slack->talk( $slack );

		return false;
	}
}

/**
 * Stablish Slack communication.
 */
class XNO_Slack {
	/**
	 * Holds Slack settions.
	 */
	private $settings;

	/**
	 * Constructor
	 *
	 * Set class variables.
	 */
	public function __construct() {
		// Channels where slack will post notifications.
		$channels = getenv( 'XCHANNELS', true ) ? json_decode( getenv( 'XCHANNELS', true ), true ) : array();

		// Users that will be notified.
		$notify = getenv( 'XNOTIFY_USERS', true ) ? json_decode( getenv( 'XNOTIFY_USERS', true ), true ) : array();

		// Slack endpoint.
		$slack_end_point = getenv( 'XSLACK', true ) ? : false;

		// Slack connections.
		$this->settings = array(
			'enable' => ( ! empty( $slack_end_point ) ),
			'end_point' => $slack_end_point,
			'bot_name' => 'Xeno WP Vulnerabilities',
			'bot_icon' => '',
			'channels' => $channels,
			'notify' => $notify,
		);
	}

	/**
	 * Send the notification thought Slack API.
	 *
	 * @param   array $args - slack notifications settings.
	 *
	 * @return  boolean $string - API response.
	 * @since   1.0.0
	 */
	public function talk( $args = array() ) {

		// Checks if slack notifications are enabled.
		if ( false === $this->settings['enable'] ) {
			return false;
		}

		if ( empty( $this->settings['channels']['info'] ) ) {
			echo sprintf( "\nSlack webhook missing or info channel does not exists." );
			return false;
		}

		// Verify if there are vulnerabilities.
		$vul = ( ! empty( $args['vulnerable'] ) );

		$webhook = new stdClass();

		if ( $vul ) {
			$webhook->the_icon = ':fire:';

			// Mergin users only once in case users are in noth types of notifications.
			if ( ! empty( $this->settings['notify']['fire'] ) ) {
				$webhook->the_users = array_unique(
					array_merge(
						$this->settings['notify']['info'],
						$this->settings['notify']['fire']
					),
					SORT_REGULAR
				);
			}

			// Mergin channels only once in case channels are in noth types of notifications.
			if ( ! empty( $this->settings['channels']['fire'] ) ) {
				$webhook->the_channels = array_unique(
					array_merge(
						$this->settings['channels']['info'],
						$this->settings['channels']['fire']
					),
					SORT_REGULAR
				);
			}

			$webhook->the_color = '#d52121';
		} else {
			if ( $args['fields'] ) {
				$webhook->the_users = $this->settings['notify']['info'];
				$webhook->the_color = '#ffcd00';
				$webhook->the_icon = ':mega:';
			} else {

				$args['fields'] = [
					[
						'value' => $args['the_message'],
						'short' => false,
					],
				];

				$webhook->the_color = '#36a64f';
			}

			$webhook->the_channels = $this->settings['channels']['info'];
		}

		// Slack list of users to be notified.
		$webhook->calling_users = '';
		if ( ! empty( $webhook->the_users ) ) {
			foreach ( $webhook->the_users as $users_to_notify ) {
				$webhook->calling_users .= '<@' . $users_to_notify . '> ';
			}
		}

		// fields.
		if ( ! empty( $args['fields'] ) ) {
			$the_attachments = array(
				[
					'fallback' 	=> get_bloginfo( 'url' ),
					'color' 	=> $webhook->the_color,
					'fields' => $args['fields'],
				],
			);
		}

		// Slack defualts.
		$defauls = array(
			'username' => $this->settings['bot_name'],
			'text' => sprintf( '*<%1$s|%2$s>*' . "\n" . '%3$s', get_bloginfo( 'url' ), get_bloginfo( 'name' ), $webhook->calling_users ),
			'color' => $webhook->the_color,
		);

		if ( ! empty( $the_attachments ) ) {
			$defauls['attachments'] = $the_attachments;
		}

		// Loops betwwen slack channels.
		foreach ( $webhook->the_channels as $channel ) {

			$defauls['channel'] = $channel;

			$api_response = wp_remote_post(
				$this->settings['end_point'],
				[
					'method'      => 'POST',
					'timeout'     => 30,
					'httpversion' => '1.0',
					'blocking'    => true,
					'headers'     => array(),
					'body'        => [
						'payload' => json_encode( $defauls ),
					],
				]
			);
		}

		// Checks for errors.
		if ( is_wp_error( $api_response ) ) {
			echo sprintf( 'API ERROR: %s', $api_response->get_error_message() );
		}

		return true;
	}
}

/**
 * Stablish Jira communication.
 */
class XNO_Jira {

	/**
	 * Holds Jira settions.
	 */
	private $settings;

	/**
	 * Holds Jira task description.
	 */
	private $description = '';

	/**
	 * Constructor
	 *
	 * Set class variables.
	 */
	public function __construct() {
		// Jira server host.
		$this->settings = getenv( 'XJIRA', true ) ? json_decode( getenv( 'XJIRA', true ), true ) : false;

		if ( empty( $this->settings['progress_transition_id'] ) ) {
			$this->settings['progress_transition_id'] = 4; // Jira transition ID for Start Progress, default 4.
		}
	}

	public function set_description( $desc ) {
		$this->description = sprintf( "%s\n%s", $this->description, $desc );
	}

	/**
	 * Open Jira task and start progress.
	 *
	 * @param   boolean $vulnerable - If the site is vulnerable then the priority
	 *			will be the highest oneotherwise medium.
	 * @return  string  $response - APi response.
	 * @since   1.0.0
	 */
	public function open_task( $vulnerable ) {

		// Checks if slack notifications are enabled.
		if ( empty( $this->description ) || empty( $this->settings ) ) {
			return false;
		}

		if ( empty( $this->settings['user'] ) || empty( $this->settings['pwd'] ) || empty( $this->settings['server'] ) ) {
			echo sprintf( "\nJira information incomplete." );
			return false;
		}

		// Verify if there are vulnerabilities.
		$data = array(
			'fields' => array(
				'priority' => [ 'id' => ( true === $vulnerable ) ? '1' : '3' ],
				'assignee' => [ 'name' => ( isset( $this->settings['assignee'] ) ? $this->settings['assignee'] : 'admin' ) ],
				'project' => [
					'key' => $this->settings['project'],
				],
				'labels' => $this->settings['labels'],
				'summary' => sprintf( 'WP updates -- %s', get_option( 'blogname' ) ),
				'description' => $this->description,
				'issuetype' => [
					'name' => ( true === $vulnerable ) ? 'Bug' : 'Task',
				],
			),
		);

		// safety.
		$server = trailingslashit( $this->settings['server'] );

		$url = $server . 'rest/api/latest/issue';

		$response = $this->curl( $url, json_encode( $data ) );

		if ( false !== $response ) {

			$jira_id = json_decode( $response );

			if ( isset( $jira_id->key ) ) {

				$data = '{"update": {"comment": [{"add": {"body": "Starts progress automatically"}}]},"transition": {"id": "' . $this->settings['progress_transition_id'] . '"}}';

				$url = $server . 'rest/api/latest/issue/' . $jira_id->key . '/transitions?expand=transitions.fields';

				$jira_id = $this->curl( $url, $data );

			}
		}

		return $response;
	}

	/**
	 * cURL function to all Jira rest API.
	 * TODO conver to wp.
	 *
	 * @param $url string - jira rest api.
	 * @param $data json - string with fields.
	 *
	 * @return $result json - string or boolean.
	 */
	private function curl( $url, $data ) {

		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_POST, 1 );
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_USERPWD, $this->settings['user'] . ':' . $this->settings['pwd'] );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $data );
		curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-type: application/json' ) );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		// curl_setopt( $ch, CURLOPT_VERBOSE, 1 );

		$result = curl_exec( $ch );
		$ch_error = curl_error( $ch );

		if ( $ch_error ) {
		    echo sprintf( 'cURL Error: %s', $ch_error );
		    return false;
		}

		curl_close( $ch );

		echo "\n" . $result;

		return $result;
	}
}
