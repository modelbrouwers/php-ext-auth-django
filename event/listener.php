<?php
/**
*
* @package phpBB Extension - modelbrouwers Auth Django
* @copyright (c) 2016 Sergei Maertens
* @license http://opensource.org/licenses/MIT MIT License
*
*/
namespace modelbrouwers\authdjango\event;


/**
* @ignore
*/
use Symfony\Component\EventDispatcher\EventSubscriberInterface;


class listener implements EventSubscriberInterface
{

    /**
     * phpBB config
     *
     * @var \phpbb\config\config
     */
    protected $config;

    /**
     * phpBB template object
     *
     * @var \phpbb\template\twig\twig
     */
    protected $template;

    /**
     * phpBB user object
     *
     * @var \phpbb\user
     */
    protected $user;


    public function __construct(
        \phpbb\config\config $config,
        \phpbb\template\twig\twig $template,
        \phpbb\user $user,
        $php_ext
    ) {
        $this->config = $config;
        $this->template = $template;
        $this->user = $user;
        $this->php_ext = $php_ext;
    }

    static public function getSubscribedEvents()
    {
        return array(
            'core.page_footer'          => 'core_page_footer',
        );
    }

    public function core_page_footer($event)
    {

        if ($this->user->data['user_id'] != ANONYMOUS) {
            $u_login_logout = $this->config['auth_django_logout_url'];
        } else {
            $phpbb_url = sprintf('%s/%s.%s', generate_board_url(), 'index', $this->php_ext);
            $u_login_logout = sprintf('%s=%s', $this->config['auth_django_login_url'] ?: '/login/?next', urlencode($phpbb_url));
        }

        $this->template->assign_vars(array(
            'U_REGISTER' => $this->config['auth_django_register_url'],
            'U_LOGIN_LOGOUT' => $u_login_logout,
        ));

    }
}
