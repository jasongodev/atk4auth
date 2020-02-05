<?php
namespace sirjasongo\atk4auth;

/**
 * Undocumented class
 */
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
        'pretty_links' => true,
        'base_url' => '',
        'get_auth' => 'auth',
        'get_method' => 'method',
        'get_redirect' => 'redirect',
        'login_slug' => 'login',
        'logout_slug' => 'logout',
        'register_slug' => 'register',
        'passwordless_slug' => 'link',
        '2fa_slug' => '2fa',
        'template' => __DIR__ . '/../template/narrow.html',
        'user_id_field' => 'id',
        'user_password_field' => 'password',
        'user_password_encryption' => PASSWORD_DEFAULT,
        'user_email_field' => 'email',
        'user_enable_2fa_field' => 'enable_2fa',
        'enable_2fa' => 2, // 0=Disable, 1=Optional, 2=Mandatory

        //Providers specifics
        'providers' => [
            'Google'   => ['enabled' => true, 'keys' => [ 'id'  => '939432130054-j1qlru36qjjqnhr7pcvpr7bsvt2f7cac.apps.googleusercontent.com', 'secret' => 'j5FBCCEtruFaisE2ImXBfjhR']],
            'Discord'   => ['enabled' => true, 'keys' => [ 'id'  => '674366217842196500', 'secret' => 'JF3v87lwo-IHozOAcM0KAgYNzZZOKvOq']],
            'Facebook' => ['enabled' => true, 'keys' => [ 'id'  => '548506092419505', 'secret' => '70644d05950262d932f7a2329845ffb9']],
        ]
    ];
    public $auth_user = null;
    public $slug = null;
    public $method = null;
    private $ga = null;
    private $ga_secret = null;
    
    /**
     * Undocumented function
     *
     * @param [type] $user
     * @param array $config
     */
    public function __construct(&$user, $config = [])
    {
        $this->user = $user;
        $this->config = empty($config) ? $this->default_config : $config;
        $this->config['base_url'] = empty($this->config['base_url']) ? $_SERVER['SERVER_NAME'] : $this->config['base_url'];
        $this->config['callback'] = 'https://' . $this->config['base_url'] . '/?authcallback';
    }
    
    /**
     * Undocumented function
     *
     * @return void
     */
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
        
        // Create an instance of this Authentication module inside the primary ATK4 app.
        $this->app->auth = &$this;

        // Check what authentication step and method is requested.
        // Note that this respects pretty links.
        // Set the $this->config['pretty_links'] accordingly.
        preg_match('/\/(.+?)(\/.+\.php)*(\/.*)*$/', $this->getRequestURI(), $matches);
        $this->slug = $this->config['pretty_links'] ? @$matches[1] : @$_GET[$this->config['get_auth']];
        $this->method = $this->config['pretty_links'] ? str_replace('/', '', @$matches[3]) : @$_GET[$this->config['get_method']];

        // Any mention of logout will instantly logout the user.
        if ($this->slug==$this->config['logout_slug']) {
            $_SESSION = [];
        }

        // Callbacks from third party providers will be processed regardless of login status.
        if (isset($_GET['authcallback'])) {
            $account = $this->loginByProvider($_SESSION['auth_current_method'], true);
            if ($account->isConnected()) {
                
                // Not all callbacks are about initial logins. The initial login process should set
                // $_SESSION['auth_login_process'] to true to distinguish it from callbacks initiated by re-authentication.
                if ($_SESSION['auth_login_process']) {

                    // Check if email is present in the database.
                    $this->user->tryLoadBy($this->config['user_email_field'], $account->getUserProfile()->email);

                    if ($this->user->loaded()) {
                        $_SESSION['auth_user_id'] = $this->user[$this->config['user_id_field']];
                        $_SESSION['auth_login_process'] = false;
                        $this->app->redirect('https://' . $this->config['base_url']);
                    } else {
                        $this->app->redirect($this->getAuthURI('login'));
                    }
                } else {
                    $r = $_SESSION['auth_redirect'];
                    unset($_SESSION['auth_redirect']);
                    $this->app->redirect($r);
                }
            }
        }

        // Check if the user is logged in. $_SESSION['auth_user_id'] contains the user id of the logged user.
        if (!empty($_SESSION['auth_user_id'])) {
            $this->user->load($_SESSION['auth_user_id']);
            $this->auth_user = clone $this->user;
            $this->user->unload();
            $this->loginBy2FA('primary_2fa');
        } else {

            // Maybe this will be handy in the future. Hooks can access this object properties via $app->auth.
            $this->app->hook('beforeAuthentication');

            //$auth_app = null;

            // Login with empty method defaults to password-based logins.
            if ($this->slug==$this->config['login_slug'] and empty($this->method)) {
                $this->loginByPassword('primary');

            // Login with method is passed to the Hybridauth3 third party authentication
            } elseif ($this->slug==$this->config['login_slug'] and array_key_exists($this->method, $this->config['providers']) and $this->config['providers'][$this->method]['enabled']==true) {
                $_SESSION['auth_login_process'] = true;
                $this->loginByProvider($this->method, true);

            // Password-less, login by email link.
            } elseif ($this->slug==$this->config['passwordless_slug']) {
                $this->loginByLink('primary');

            // Very basic registration form.
            } elseif ($this->slug==$this->config['register_slug']) {
            
            // Catch orphan atk callbacks and redirect to login page.
            } elseif (isset($_GET['__atk_reload']) or isset($_GET['__atk_callback'])) {
                // The only code that works!
                $this->app->add(['template'=>new \atk4\ui\Template('<style>body{display: none !important;}</style><script>document.location = "' . $this->getAuthURI('login') . '";</script>')]);
                $this->app->run();
            
            // Catches any url that needs authentication.
            } else {
                $this->app->redirect($this->getAuthURI('login'));
            }
            //$auth_app->run();
            exit;
        }
    }

    /**
     * Undocumented function
     *
     * @param [type] $target_lock
     * @return void
     */
    public function loginByPassword($target_lock)
    {
        if (!empty($_SESSION[$target_lock])) {
            return true;
        }
        $auth_app = null;
        // Create a new atk4/ui app for the login form.
        $this->initializeTemplate($auth_app, 'Login');
        $form = $auth_app->add('Form');
        $form->buttonSave->set('Sign in');
        $form->buttonSave->addClass('large fluid green');
        $form->buttonSave->iconRight = 'right arrow';
        $form->addField('email', null, ['required' => true]);
        $p = $form->addField('password', ['Password'], ['required' => true]);
        $reset_button = $p->addAction(['icon' => 'question'])->setAttr('title', 'Forgot your password?');
        $b_pop = $auth_app->add(['Popup', $reset_button, 'minWidth'=>'50%', 'position' => 'bottom left']);
        $b_pop->add('Header')->set('Forgot Password?');
        $b_pop->add('View')->set('Type your user email to receive an email link.');
        $b_pop->add(['Button', 'Login via Email Link', 'red fluid'])->link($this->getAuthURI($this->config['passwordless_slug']));
        
        if ($target_lock=='primary') {
            $auth_app->add(['template'=>new \atk4\ui\Template('<div class="ui horizontal divider">Or Login Via</div>')]);
            $social_col = $auth_app->add(new \atk4\ui\Columns(['width'=>2]))->addClass('center aligned stackable');
            $social_col->addColumn()->add(['Button', 'Facebook', 'facebook large fluid', 'icon'=>'facebook'])->link($this->getAuthURI('login', 'Facebook'));
            $social_col->addColumn()->add(['Button', 'Google', 'google large fluid red', 'icon'=>'google'])->link($this->getAuthURI('login', 'Google'));
            $social_col->addColumn()->add(['Button', 'Discord', 'discord large fluid dark blue', 'icon'=>'discord'])->link($this->getAuthURI('login', 'Discord'));
        }

        $form->onSubmit(function ($form) use (&$auth_app, $target_lock) {
            if (empty($_SESSION['primary'])) {
                $this->user->tryLoadBy($this->config['user_email_field'], $form->model['email']);
            } else {
                $this->user->tryLoadBy($this->config['user_id_field'], $_SESSION['auth_user_id']);
            }
            
            
            if ($this->user->loaded() and password_verify($form->model['password'], $this->user[$this->config['user_password_field']])) {
                $_SESSION['auth_user_id'] = $this->user[$this->config['user_id_field']];
                $_SESSION[$target_lock] = true;
                return new \atk4\ui\jsExpression('$(".ui, div").hide();document.location = []', ['https://' . $this->config['base_url'] . ($target_lock!='primary' ?  $this->getRequestURI() : '')]);
            } else {
                return (new \atk4\ui\jsNotify('Invalid credentials.'))
                        ->setColor('red')
                        ->setPosition('topCenter')
                        ->setWidth('50')
                        ->setTransition('jiggle')
                        ->setIcon('warning sign');
            }
        });

        $auth_app->run();
        exit;
    }

    public function loginByLink($target_lock)
    {
        if (!empty($_SESSION[$target_lock])) {
            return true;
        }
        $auth_app = null;
        // Create a new atk4/ui app for the login form.
        $this->initializeTemplate($auth_app, 'Login By Link');
        $form = $auth_app->add('Form');
        $form->buttonSave->set('Send Link to Email');
        $form->buttonSave->addClass('large fluid green');
        $form->buttonSave->iconRight = 'right arrow';
        $form->addField('email', null, ['required' => true]);

        $form->onSubmit(function ($form) use (&$auth_app, $target_lock) {
            if (empty($_SESSION['primary'])) {
                $this->user->tryLoadBy($this->config['user_email_field'], $form->model['email']);
            } else {
                $this->user->tryLoadBy($this->config['user_id_field'], $_SESSION['auth_user_id']);
            }
            
            
            if ($this->user->loaded()) {


                //return new \atk4\ui\jsExpression('$(".ui, div").hide();document.location = []', ['https://' . $this->config['base_url'] . ($target_lock!='primary' ?  $this->getRequestURI() : '')]);
            }

            return (new \atk4\ui\jsNotify('You will receive the login link to your email if this is registered in our system.'))
            ->setColor('blue')
            ->setPosition('topCenter')
            ->setWidth('50')
            ->setTransition('jiggle')
            ->setIcon('info sign');
        });

        $auth_app->run();
        exit;
    }

    /**
     * Undocumented function
     *
     * @param [type] $target_lock
     * @return void
     */
    public function loginBy2FA($target_lock)
    {
        if (!empty($_SESSION[$target_lock])) {
            return true;
        }

        if ($this->config['enable_2fa']==2 or ($this->auth_user[$this->config['user_enable_2fa_field']] and $this->config['enable_2fa']==1)) {
            $ga = new \PHPGangsta_GoogleAuthenticator();
            $ga_secret = $this->auth_user['totp_secret'];

            // Create a new atk4/ui app for the 2FA form.
            $auth_app = null;
            $this->initializeTemplate($auth_app, '2FA');

            $form = $auth_app->add('Form');
            //$qrCodeUrl = $ga->getQRCodeGoogleUrl($this->app->title, $ga_secret);
            //$form->add(['template'=>new \atk4\ui\Template('<img src="' . $qrCodeUrl . '" />')]);

            $form->addField('code', '2FA Code', ['required' => true]);
            $form->buttonSave->set('Verify');
            $form->buttonSave->addClass('large fluid green');
            $form->buttonSave->iconRight = 'right arrow';
            $form->onSubmit(function ($form) use ($ga, $ga_secret, $target_lock) {
                if ($ga->verifyCode($ga_secret, $form->model['code'], 2)) {
                    $_SESSION[$target_lock] = true;
                    return new \atk4\ui\jsExpression('$(".ui, div").hide();document.location = []', ['https://' . $this->config['base_url'] . ($target_lock!='primary_2fa' ?  $this->getRequestURI() : '')]);
                } else {
                    return (new \atk4\ui\jsNotify('Invalid Code'))->setColor('red')
                            ->setColor('red')
                            ->setPosition('topCenter')
                            ->setWidth('50')
                            ->setTransition('jiggle')
                            ->setIcon('warning sign');
                }
            });
            $auth_app->run();
            exit;
        }
    }

    /**
     * Undocumented function
     *
     * @param [type] $method
     * @param boolean $from_callback
     * @return void
     */
    public function loginByProvider($method, $from_callback = false)
    {
        // $redirect_uri should be supplied during re-authentication calls anywhere in the atk4/ui pages.
        // The login routines above do not pass a $redirect_uri because it defaults to the $config['base_url'].
        // Also, the only way we can remember the $redirect_uri is to pass it to $_SESSION['auth_redirect']
        // so that when the callback is triggered, we can redirect the user to the appropriate pages.
        // Note that we can't attach any url redirect to the callback url because third party providers
        // usually need a constant callback url.
        $_SESSION['auth_redirect'] = $from_callback ? $_SESSION['auth_redirect'] : $this->getRequestURI();
        $_SESSION['auth_current_method'] = $method;
        
        try {
            $hybridauth = new \Hybridauth\Hybridauth($this->config);

            // If the user is not yet authenticated, this will force the browser to redirect to the
            // login pages of the third party provider. Then the callback above will call this
            // loginByProvider($method) again. This time the command $hybridauth->authenticate already
            // knows that the user is authenticated and therefore proceeds with returning of the $adapter.
            $adapter = $hybridauth->authenticate($method);

            // Will only execute if the $hybridauth->authenticate($method) is successful.
            return $adapter;
        } catch (\Exception $e) {
            echo 'Oops, we ran into an issue! ' . $e->getMessage();
            return false;
        }
    }

    /**
     * Undocumented function
     *
     * @param [type] $auth_app
     * @param string $title
     * @return void
     */
    private function initializeTemplate(&$auth_app, $title = 'Authentication')
    {
        // Create a new atk4/ui app for the login or registration form.
        $auth_app = new \atk4\ui\App($title . ' - ' . $this->app->title);
        $this->app->catch_runaway_callbacks = false;
        $this->app->run_called = true;
        $auth_app->catch_runaway_callbacks = false;

        // Load the page template. Can be overriden by $this->config['template'].
        $auth_app->initLayout(new \atk4\ui\View(['defaultTemplate' => $this->config['template']]));

        // Super important!
        // atk4/ui callbacks do not know the authentication step or method for non-pretty links.
        // Without these, the callbacks will slip through the if-then-else filter below, never to be executed.
        $auth_app->stickyGet($this->config['get_auth']);
        $auth_app->stickyGet($this->config['get_method']);
        $auth_app->stickyGet($this->config['get_redirect']);
    }

    /**
     * Undocumented function
     *
     * @param [type] $slug
     * @param string $method
     * @return void
     */
    public function getAuthURI($slug, $method = '')
    {
        return 'https://' . $this->config['base_url'] . ($this->config['pretty_links'] ? '/' . $slug . '/' . $method : '?' . $this->config['get_auth'] . '=' . $slug . '&' . $this->config['get_method'] . '=' . $method);
    }

    /**
     * Undocumented function
     *
     * @return void
     */
    protected function getRequestURI()
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
}
