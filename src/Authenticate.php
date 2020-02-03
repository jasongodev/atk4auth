<?php
namespace sirjasongo\atk4auth;

class Authenticate
{
    use \atk4\core\SessionTrait;
    use \atk4\core\ContainerTrait;
    use \atk4\core\FactoryTrait;
    use \atk4\core\AppScopeTrait;
    use \atk4\core\DIContainerTrait;
    use \atk4\core\TrackableTrait;
    use \atk4\core\HookTrait;
    use \atk4\core\InitializerTrait {
        init as _init;
    }

    public $config = null;
    public $user = null;
    public $default_config = [
        'pretty_links' => false,        
        'base_url' => '',
        'get_auth' => 'auth',
        'get_method' => 'method',
        'login_slug' => 'login',
        'register_slug' => 'register',
        '2fa_slug' => '2fa',
        'template' => __DIR__ . '/../template/narrow.html',
        'social_logins' => [],
        'user_id_field' => 'id',
        'user_password_field' => 'password',
        'user_password_encryption' => PASSWORD_DEFAULT,
        'user_email_field' => 'email',
        'user_enable_2fa_field' => 'enable_2fa',
        'social_logins' => [],
        'enable_2fa' => 0, // 0=Disable, 1=Optional, 2=Mandatory
    ];
    public $auth_user = null;
    public $slug = null;
    public $method = null;
    private $ga = null;
    private $ga_secret = null;
    
    public function __construct(&$user, $config = [])
    {
        $this->user = $user;
        $this->config = empty($config) ? $this->default_config : $config;
        $this->config['base_url'] = empty($this->config['base_url']) ? $_SERVER['SERVER_NAME'] : $this->config['base_url'];
    }
    
    public function init()
    {
        $this->_init();
        switch (session_status()) {
            case PHP_SESSION_DISABLED:
                throw new \atk4\core\Exception(['Sessions are disabled on server']);
                break;
            case PHP_SESSION_NONE:
                session_start();
                break;
        }
        
        if (!empty($_SESSION['auth_user_id'])) {
            $this->user->load($_SESSION['auth_user_id']);
            if ($this->config['enable_2fa']==2 or ($this->user[$this->config['user_enable_2fa_field']] and $this->config['enable_2fa']==1)) {
                if (empty($_SESSION['auth_user_2fa'])) {
                    $ga = new \PHPGangsta_GoogleAuthenticator();
                    $ga_secret = 'VE2E3TSCDEKIIA5G'; //$this->user['totp_secret']; //$ga->createSecret();

                    $form = $auth_app->add('Form');
                        $form->buttonSave->set('Verify');
                        $form->buttonSave->addClass('large fluid green');
                        $form->buttonSave->iconRight = 'right arrow';
                                        
                    $form->add('Header')->set($ga_secret);
                    $qrCodeUrl = $ga->getQRCodeGoogleUrl($this->app->title, $ga_secret);
                    $form->add(['template'=>new \atk4\ui\Template('<img src="' . $qrCodeUrl . '" />')]);
                    $form->addField('code', '2FA Code', ['required' => true]);
                    $form->onSubmit(function ($form) use ($ga, $ga_secret) {
                        if ($ga->verifyCode($ga_secret, $form->model['code'], 2)) {
                            return new \atk4\ui\jsNotify('Code is Valid');
                        } else {
                            return (new \atk4\ui\jsNotify('Invalid Code'))->setColor('red');
                        }
                    });
                }
            }
            $this->auth_user = clone $this->user;
            $this->user->unload();
        } else {
            $auth_app = new \atk4\ui\App('Login - ' . $this->app->title);
            $this->app->catch_runaway_callbacks = false;
            $this->app->run_called = true;
            $auth_app->catch_runaway_callbacks = false;
            $auth_app->initLayout(new \atk4\ui\View(['defaultTemplate' => $this->config['template']]));

            $auth_app->stickyGet($this->config['get_auth']);
            $auth_app->stickyGet($this->config['get_method']);

            preg_match('/^\/(.+?)(\.php)*(\/.*)*$/', strtolower($this->getRequestURI()), $matches);
            $this->slug = $this->config['pretty_links'] ? @$matches[1] : @$_GET[$this->config['get_auth']];
            $this->method = $this->config['pretty_links'] ? str_replace('/', '', @$matches[3]) : @$_GET[$this->config['get_method']];
            
            $this->app->auth = &$this;
            $this->app->hook('beforeAuthentication');

            if ($this->slug==$this->config['login_slug'] and empty($this->method))
            {
                $form = $auth_app->add('Form');
                $form->buttonSave->set('Sign in');
                $form->buttonSave->addClass('large fluid green');
                $form->buttonSave->iconRight = 'right arrow';
                
                $auth_app->add(['template'=>new \atk4\ui\Template('<div class="ui horizontal divider">Or Login Via</div>')]);
            
                $social_col = $auth_app->add(new \atk4\ui\Columns(['width'=>2]))->addClass('center aligned stackable');
                $social_col->addColumn()->add(['Button', 'Facebook', 'facebook large fluid', 'icon'=>'facebook']);
                $social_col->addColumn()->add(['Button', 'Twitter', 'twitter large fluid', 'icon'=>'twitter']);
                $social_col->addColumn()->add(['Button', 'LinkedIn', 'linkedin large fluid', 'icon'=>'linkedin']);
                $social_col->addColumn()->add(['Button', 'GitHub', 'github large fluid', 'icon'=>'github']);
                $social_col->addColumn()->add(['Button', 'Discord', 'discord large fluid black', 'icon'=>'discord']);
                $social_col->addColumn()->add(['Button', 'Yahoo', 'yahoo large fluid violet', 'icon'=>'yahoo']);
                                                
                $form->addField('email', null, ['required' => true]);
                $p = $form->addField('password', ['Password'], ['required' => true]);
                
                $reset_button = $p->addAction(['icon' => 'question'])->setAttr('title', 'Forgot your password?');
            
                
                $b_pop = $auth_app->add(['Popup', $reset_button, 'minWidth'=>'50%', 'position' => 'bottom left']);

                $b_pop->add('Header')->set('Forgot Password?');
                $b_pop->add('View')->set('Type your user email to receive an email link.');
                $b_pop->add(['Button', 'Login via Email Link', 'red fluid']);

                $form->onSubmit(function ($form) use ($auth_app) {
                    $this->user->tryLoadBy($this->config['user_email_field'], $form->model['email']);
                    
                    if ($this->user->loaded()) {
                        //if ($this->user->compare($this->config['user_password_field'], $form->model['password'])) {
                        if (password_verify($form->model['password'], $this->user[$this->config['user_password_field']])) {
                            $_SESSION['auth_user_id'] = $this->user[$this->config['user_id_field']];
                            $auth_app->jsRedirect($this->config['base_url']);
                        }
                        return (new \atk4\ui\jsNotify($this->user[$this->config['user_password_field']]))->setColor('red');
                    }
                    else
                    {
                        return (new \atk4\ui\jsNotify('Invalid Login'))->setColor('red');
                    }
                });
            }
            else if ($this->slug==$this->config['login_slug'] and in_array($this->method, $this->config['social_logins']))
            {


            }
            else if ($this->slug==$this->config['register_slug'])
            {

            }
            else
            {
                $auth_app->redirect($this->getAuthURI('login'));
            }      

            $auth_app->run();
            $this->app->terminate();
            exit;
        }
    }
    public function getRequestURI()
    {
        if (isset($_SERVER['HTTP_X_REWRITE_URL'])) { // IIS
            $request_uri = $_SERVER['HTTP_X_REWRITE_URL'];
        } elseif (isset($_SERVER['REQUEST_URI'])) { // Apache
            $request_uri = $_SERVER['REQUEST_URI'];
        } elseif (isset($_SERVER['ORIG_PATH_INFO'])) { // IIS 5.0, PHP as CGI
            $request_uri = $_SERVER['ORIG_PATH_INFO'];
        // This one comes without QUERY string
        } else {
            $request_uri = '';
        }
        $request_uri = explode('?', $request_uri, 2);
 
        return $request_uri[0];
    }

    public function getAuthURI ($slug) {
        return 'https://' . $this->config['base_url'] . '/' . ($this->config['pretty_links'] ? $slug : '?' . $this->config['get_auth'] . '=' . $slug);
    }
}

