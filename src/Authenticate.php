<?php
namespace sirjasongo\atk4auth;

class Authenticate
{
    public function __construct($app, $user, $config = [])
    {
        ob_start();
        var_dump($user);
	$data = ob_get_contents();
	ob_clean();
	$app->add(['View', 'template' => new \atk4\ui\Template($data)]);
    }

}

?>