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
        \phpbb\config\config $config,
        \phpbb\request\request $request,
        \phpbb\user $user,
        $phpbb_root_path,
        $php_ext
    ) {
        $this->config = $config;
        $this->request = $request;
        $this->user = $user;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;

        $this->settings['db_name'] = $this->config['auth_django_db_name'] ?: 'sessionid';
        $this->settings['db_user'] = $this->config['auth_django_db_user'] ?: 'sessionid';
        $this->settings['db_passwd'] = $this->config['auth_django_db_passwd'] ?: 'sessionid';
        $this->settings['cookie_name'] = $this->config['auth_django_cookie_name'] ?: 'sessionid';

        $this->pg_session = pg_connect("dbname={$this->settings['db_name']} user=${this->settings['db_user']} password={$this->settings['db_passwd']}");
        if(!$this->pg_session) {
            throw new Exception("cannot connect to Postgres db: " . pg_last_error());
        }
    }
}
