<?php
/**
*
* @package phpBB Extension - modelbrouwers Auth Django
* @copyright (c) 2016 Sergei Maertens
* @license http://opensource.org/licenses/MIT MIT License
*
*/
if(!defined('IN_PHPBB'))
{
    exit;
}

if(empty($lang) || !is_array($lang))
{
    $lang = array();
}

$lang = array_merge($lang, array(
    'LOGIN_ERROR_EXTERNAL_AUTH' => 'Je bent niet ingelogd in Django.',
));
