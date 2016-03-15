<?php
/**
*
* @package phpBB Extension - modelbrouwers Auth Django
* @copyright (c) 2016 Sergei Maertens
* @license http://opensource.org/licenses/MIT MIT License
*
*/
namespace modelbrouwers\authdjango\auth\provider;

use phpbb\request\request_interface;


/**
 * Django authentication provider for phpBB 3.1
 */
class django extends \phpbb\auth\provider\base
{
    /**
     * phpBB config
     *
     * @var \phpbb\config\config
     */
    protected $config;

    /**
     * phpBB request object
     *
     * @var \phpbb\request\request
     */
    protected $request;

    /**
     * phpBB user object
     *
     * @var \phpbb\user
     */
    protected $user;

    /**
     * phpBB root path
     *
     * @var string
     */
    protected $phpbb_root_path;

    /**
     * php file extension
     *
     * @var string
     */
    protected $php_ext;

    /**
     * auth adapter settings
     *
     * @var array
     */
    protected $settings = array();

    /**
     * External DB session
     *
     * @var resource
     */
    protected $pg_session = null;


    /**
     * Django Authentication Constructor
     *  - called when instance of this class is created
     *
     * @param   \phpbb\config\config      $config             Config object
     * @param   \phpbb\request\request    $request            Request object
     * @param   \phpbb\user               $user               User object
     * @param   string                    $phpbb_root_path    Relative path to phpBB root
     * @param   string                    $php_ext            PHP file extension
     */
    public function __construct(
        \phpbb\db\driver\driver_interface $db,
        \phpbb\config\config $config,
        \phpbb\request\request $request,
        \phpbb\user $user,
        $phpbb_root_path,
        $php_ext
    ) {
        $this->db = $db;
        $this->config = $config;
        $this->request = $request;
        $this->user = $user;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;

        $this->user->add_lang_ext('modelbrouwers/authdjango', 'common');

        $db_name = $this->config['auth_django_db_name'];
        $db_user = $this->config['auth_django_db_user'];
        $db_passwd = $this->config['auth_django_db_passwd'];
        $this->settings['cookie_name'] = $this->config['auth_django_cookie_name'] ?: 'sessionid';

        $this->pg_session = pg_connect("dbname={$db_name} user={$db_user} password={$db_passwd}");
        // if(!$this->pg_session) {
        //     throw new Exception("cannot connect to Postgres db: " . pg_last_error());
        // }
    }

    public function __destruct()
    {
        if ($this->pg_session) {
            pg_close($this->pg_session);
        }
    }

    /**
     * {@inheritdoc}
     * - called when authentication method is enabled
     */
    public function init()
    {
        // check if the user is currently authenticated in Django to prevent lock out
        $django_user = $this->get_django_user();
        if ($django_user['username'] !== $this->user->data['username']) {
            return 'Incorrect or no admin user retrieved - check the Postgres database credentials';
        }
        return false;
    }

    /**
     * {@inheritdoc}
     * - called when login form is submitted (is also the case for ACP)
     */
    public function login($username = null, $password = null)
    {
        $django_user = $this->get_django_user();

        if ($django_user) {
            if ($django_user['username'] !== $username) {
                return array(
                    'status'    => LOGIN_ERROR_USERNAME,
                    'error_msg' => 'LOGIN_ERROR_USERNAME',
                    'user_row'  => array('user_id' => ANONYMOUS),
                );
            } else {
                $row = $this->get_phpbb_user($django_user);
                if ($row) {
                    // success
                    return array(
                        'status'        => LOGIN_SUCCESS,
                        'error_msg'     => false,
                        'user_row'      => $row,
                    );
                }
            }
        }

        // Fallback, not logged in
        return array(
            'status'    => LOGIN_ERROR_USERNAME,
            'error_msg' => 'LOGIN_ERROR_EXTERNAL_AUTH',
            'user_row'  => array('user_id' => ANONYMOUS),
        );
    }

    /**
     * {@inheritdoc}
     - called when new session is created
     */
    public function autologin()
    {
        $django_user = $this->get_django_user();
        if (!$django_user) {
            return array();
        }

        $username_clean = utf8_clean_string($username);
        $row = $this->get_phpbb_user($django_user);

        // user exists
        if($row) {
            // check for inactive users
            if($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) {
                return array();
            }

            // success
            return $row;
        }

        // user does not exist atm, we'll fix that
        if(!function_exists('user_add'))
        {
            include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
        }

        $username = $django_user['username']; // can be multibyte
        $email = $django_user['email'];
        set_var($username, $username, 'string', true);
        user_add($this->create_new_user($username, $email));

        // get the newly created user row
        // $sql already defined some lines before
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if($row) {
            return $row;
        }
        return array();
    }

    /**
     * {@inheritdoc}
     * - should return custom configuration options
     */
    public function acp()
    {
        // these are fields in the config for this auth provider
        return array(
            'auth_django_db_name',
            'auth_django_db_user',
            'auth_django_db_passwd',
            'auth_django_cookie_name',
            'auth_django_login_url',
        );
    }

    /**
     * {@inheritdoc}
     * - should return configuration options template
     */
    public function get_acp_template($new_config)
    {
        return array(
            'TEMPLATE_FILE' => '@modelbrouwers_authdjango/auth_provider_django.html',
            'TEMPLATE_VARS' => array(
                'AUTH_DJANGO_DB_NAME'       => $new_config['auth_django_db_name'],
                'AUTH_DJANGO_DB_USER'       => $new_config['auth_django_db_user'],
                'AUTH_DJANGO_DB_PASSWD'     => $new_config['auth_django_db_passwd'],
                'AUTH_DJANGO_COOKIE_NAME'   => $new_config['auth_django_cookie_name'],
                'AUTH_DJANGO_LOGIN_URL'     => $new_config['auth_django_login_url'],
            ),
        );
    }

    /**
    * {@inheritdoc}
    * - should return additional template data for login form
    */
    public function get_login_data()
    {
        // if we're not trying to get access to the administration panel, redirect
        // to the configured login page
        $script = $this->request->variable(
            'SCRIPT_FILENAME', '', false,
            \phpbb\request\request_interface::SERVER
        );
        $adm_index_script = realpath($this->phpbb_root_path . 'adm/index.' . $this->php_ext);

        if ($script !== $adm_index_script) {
            // page to be sent back to
            $phpbb_url = sprintf('%s/%s.%s', generate_board_url(), 'index', $this->php_ext);
            redirect(
                sprintf('%s=%s',
                        $this->config['auth_django_login_url'] ?: '/login/?next',
                        urlencode($phpbb_url)),
                false, true
            );
            return;
        }
        return null;
    }

    /**
     * Retrieves the Django user based on the session cookie id from
     * the PostgreSQL database
     */
    private function get_django_user()
    {
        $sessionid = $this->request->variable(
            $this->settings['cookie_name'], '', false,
            \phpbb\request\request_interface::COOKIE);

        $query =
          "SELECT u.username as username, u.email as email ".
          "  FROM users_user u, sessionprofile_sessionprofile sp" .
          " WHERE sp.session_key = '" . pg_escape_string($sessionid) . "' " .
          "   AND u.id = sp.user_id
              AND u.is_active = True";

        $query_id = pg_query($this->pg_session, $query);

        if (!$query_id) {
          throw new Exception("Could not check whether user was logged in: " , pg_last_error());
        }

        $row = pg_fetch_array($query_id);
        if ($row) {
          return $row;
        }

        return null;
    }

    private function get_phpbb_user($django_user) {
        $username = $django_user['username']; // can be multibyte

        set_var($username, $username, 'string', true);

        $username_clean = utf8_clean_string($username);

        $sql = sprintf(
            'SELECT * FROM %1$s WHERE username_clean = \'%2$s\'',
            USERS_TABLE,
            $this->db->sql_escape($username_clean)
        );
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);
        return $row;
    }

    /**
     * This function generates an array which can be passed to the user_add function in order to create a user
     *
     * @param   string  $username   The username of the new user.
     * @param   string  $email      The e-mail address of the new user.
     * @return  array               Contains data that can be passed directly to the user_add function.
     */
    private function create_new_user($username, $email)
    {
        // first retrieve default group id
        $sql = sprintf('SELECT group_id FROM %1$s WHERE group_name = \'%2$s\' AND group_type = \'%3$s\'', GROUPS_TABLE, $this->db->sql_escape('REGISTERED'), GROUP_SPECIAL);
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);

        if(!$row) {
            trigger_error('NO_GROUP');
        }

        // generate user account data
        return array(
            'username'      => $username,
            'user_password' => '',
            'user_email'    => $email,
            'group_id'      => (int)$row['group_id'],
            'user_type'     => USER_NORMAL,
            'user_ip'       => $this->user->ip,
            'user_new'      => ($this->config['new_member_post_limit']) ? 1 : 0,
        );
    }
}
