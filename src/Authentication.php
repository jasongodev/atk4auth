<?php
namespace sirjasongo\atk4auth;

/**
 * Undocumented class
 */
class Authentication
{
    use \atk4\core\AppScopeTrait;
    use \atk4\core\InitializerTrait {
        init as _init;
    }

    private $default_config = [
        // Set true for systems with mod_rewrite and rewrite rules
        // (Default) Set false for query strings appearing in the url
        'pretty_links' => false,
        
        // 0 = (Default) Disable site-wide 2FA regardless of users settings
        // 1 = Let the user set 2FA settings. Disabled by default.
        // 2 = Mandatory 2FA. Users can not disable 2FA.
        '2fa_enabled' => 0,
    
        // The users table name
        'user_table' => 'user',
        // The users primary key
        'user_id_field' => 'id',
        'user_password_field' => 'password',
        'user_password_encryption' => PASSWORD_DEFAULT,
        'user_email_field' => 'email',
        'user_enable_2fa_field' => 'enable_2fa',
        'user_totp_secret_field' => 'totp_secret',
    
        // Email settings for sending login link.
        // Leaving the smtp_host blank will disable sending login links.
        'smtp_host' => '',
        'smtp_port' => '',
        'smtp_username' => '',
        'smtp_from' => '',
        'smtp_password' => '',
    
        // Google re-Captcha v.3 settings
        'grecaptcha_enabled' => false, // False by default. Get your keys from Google.
        'grecaptcha_site_key' => '', // Frontent key, included in pages
        'grecaptcha_secret_key' => '', // Server key, always hidden
    
        // Template files. Defaults to the template directory of the package assuming it resides in the root vendor directory.
        'template_password' => __DIR__ . '/vendor/sirjasongo/atk4auth/template/narrow.html',
        'template_provider' => __DIR__ . '/vendor/sirjasongo/atk4auth/template/narrow.html',
        'template_2fa' => __DIR__ . '/vendor/sirjasongo/atk4auth/template/narrow.html',
        //'template_email' => __DIR__ . '/vendor/sirjasongo/atk4auth/template/narrow.html',
    
         //Providers specifics
        'providers' => [
            'AOLOpenID'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'AOLOpenID',
                'icon' => 'dot circle outline',
                'color'=>'black'
            ],
            
            'Amazon'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Amazon',
                'icon' => 'amazon',
                'color'=>'yellow'
            ],
            
            'Authentiq'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Authentiq',
                'icon' => 'font',
                'color'=>'orange'
            ],
            
            'BitBucket'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'BitBucket',
                'icon' => 'bitbucket',
                'color'=>'blue'
            ],
            
            'Blizzard'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Blizzard',
                'icon' => 'bold',
                'color'=>'blue'
            ],
            
            'BlizzardAPAC'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'BlizzardAPAC',
                'icon' => 'bold',
                'color'=>'blue'
            ],
            
            'BlizzardEU'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'BlizzardEU',
                'icon' => 'bold',
                'color'=>'blue'
            ],
            
            'Discord'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Discord',
                'icon' => 'discord',
                'color'=>'violet'
            ],
            
            'Disqus'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Disqus',
                'icon' => 'discourse',
                'color'=>'blue'
            ],
            
            'Dribble'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Dribble',
                'icon' => 'dribble',
                'color'=>'pink'
            ],
            
            'Facebook'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Facebook',
                'icon' => 'facebook',
                'color'=>'blue'
            ],
            
            'Foursquare'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Foursquare',
                'icon' => 'foursquare',
                'color'=>'blue'
            ],
            
            'GitHub'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'GitHub',
                'icon' => 'github',
                'color'=>'black'
            ],
            
            'GitLab'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'GitLab',
                'icon' => 'gitlab',
                'color'=>'orange'
            ],
            
            'Google'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Google',
                'icon' => 'google',
                'color'=>'red'
            ],
            
            'Instagram'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Instagram',
                'icon' => 'instagram',
                'color'=>'pink'
            ],
            
            'LinkedIn'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'LinkedIn',
                'icon' => 'linkedin',
                'color'=>'blue'
            ],
            
            'Mailru'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Mailru',
                'icon' => 'envelope',
                'color'=>'blue'
            ],
            
            'MicrosoftGraph'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'MicrosoftGraph',
                'icon' => 'microsoft',
                'color'=>'orange'
            ],
            
            'ORCID'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'ORCID',
                'icon' => 'id badge',
                'color'=>'green'
            ],
            
            'Odnoklassniki'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Odnoklassniki',
                'icon' => 'odnoklassniki',
                'color'=>'orange'
            ],
            
            'Paypal'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Paypal',
                'icon' => 'paypal',
                'color'=>'black'
            ],
            
            'Reddit'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Reddit',
                'icon' => 'reddit alien',
                'color'=>'orange'
            ],
            
            'Spotify'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Spotify',
                'icon' => 'spotify',
                'color'=>'green'
            ],
            
            'StackExchange'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'StackExchange',
                'icon' => 'stack exchange',
                'color'=>'blue'
            ],
            
            'Steam'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Steam',
                'icon' => 'steam',
                'color'=>'teal'
            ],
            
            'SteemConnect'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'SteemConnect',
                'icon' => 'dot circle outline',
                'color'=>'violet'
            ],
            
            'Telegram'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Telegram',
                'icon' => 'telegram plane',
                'color'=>'blue'
            ],
            
            'Tumblr'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Tumblr',
                'icon' => 'tumblr',
                'color'=>'blue'
            ],
            
            'TwitchTV'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'TwitchTV',
                'icon' => 'twitch',
                'color'=>'violet'
            ],
            
            'Twitter'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Twitter',
                'icon' => 'twitter',
                'color'=>'blue'
            ],
            
            'Vkontakte'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Vkontakte',
                'icon' => 'vk',
                'color'=>'blue'
            ],
            
            'WeChat'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'WeChat',
                'icon' => 'wechat',
                'color'=>'green'
            ],
            
            'WeChatChina'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'WeChatChina',
                'icon' => 'wechat',
                'color'=>'green'
            ],
            
            'WindowsLive'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'WindowsLive',
                'icon' => 'windows',
                'color'=>'blue'
            ],
            
            'Wordpress'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Wordpress',
                'icon' => 'wordpress',
                'color'=>'black'
            ],
            
            'Yahoo'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Yahoo',
                'icon' => 'yahoo',
                'color'=>'violet'
            ],
            
            'Yandex'   => [
                'enabled' => false,
                'keys' => [
                    'id'  => '',
                    'secret' => ''
                ],
                'name' => 'Yandex',
                'icon' => 'yandex international',
                'color'=>'red'
            ],
            
        ],
        // ------------------ STOP ----------------------
        // The following below are usually left as it is.
        // Change only when necessary...
        // ----------------------------------------------
    
        // Base URL defaults to server name. Change this if your site resides in a subdirectory.
        'base_url' => '',
    
        // The default query string name for the slugs.
        'get_auth' => 'auth',
    
        // The default query string name for the provider method.
        'get_method' => 'method',
    
        // The default query string name for the redirect url.
        'get_redirect' => 'redirect',
    
        // The default auth slugs
        'login_slug' => 'login',
        'logout_slug' => 'logout',
        'register_slug' => 'register',
        'passwordless_slug' => 'link',
        '2fa_slug' => '2fa',
    ];
    
    public $config = null;
    public $user = null;
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
    public function __construct($obj, $config = [])
    {
        $this->config = empty($config) ? $this->default_config : $config;
        $this->config['base_url'] = 'https://' . (empty($this->config['base_url']) ? $_SERVER['SERVER_NAME'] : $this->config['base_url']);
        $this->config['callback'] = $this->config['base_url'] . '/?authcallback';
        if ($obj instanceof \atk4\data\Model) {
            $this->user = $obj;
        } elseif ($obj instanceof \atk4\data\Persistence) {
            $this->user = new \Model\User($obj, ['table'=>'user', 'config' => $this->config]);
        }
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
            $this->app->redirect($this->getAuthURI('login'));
        }

        // Callbacks from third party providers will be processed regardless of login status.
        if (isset($_GET['authcallback'])) {
            $account = $this->gotoProvider($_SESSION['auth_current_target'], $_SESSION['auth_current_method'], true);
            if ($account->isConnected()) {

                // If primary login, load the record using the email
                if (empty($_SESSION['auth_session']['primary'])) {
                    $this->user->tryLoadBy($this->config['user_email_field'], $account->getUserProfile()->email);
                } else {
                    // Else, load the auth_user_id, then compare the email later
                    $this->user->tryLoadBy($this->config['user_id_field'], $_SESSION['auth_user_id']);
                }

                if ($this->user->loaded() and $this->user['email']==$account->getUserProfile()->email) {
                    $_SESSION['auth_user_id'] = $this->user[$this->config['user_id_field']];
                    $_SESSION['auth_session'][$_SESSION['auth_current_target']] = true;
                    $r = $_SESSION['auth_redirect'];
                    unset($_SESSION['auth_redirect']);
                    $this->app->redirect($r);
                } else {
                    $auth_app = null;
                    $this->initializeTemplate($auth_app, 'Login');
                    $auth_app->add('Header')->set('Your login via ' . $_SESSION['auth_current_method'] . ' failed.')->addClass('center aligned');
                    $auth_app->add('Button', ['Try Again', 'red fluid'])->link($_SESSION['auth_redirect']);
                    unset($_SESSION['HYBRIDAUTH::STORAGE']);
                    exit;
                }
            }
        }
        if ($this->slug=='relogin' and array_key_exists($this->method, $this->config['providers']) and $this->config['providers'][$this->method]['enabled']==true) {
            unset($_SESSION['HYBRIDAUTH::STORAGE']);
            $this->gotoProvider($_SESSION['auth_current_target'], $this->method);
        }

        // Check if the user is logged in. $_SESSION['auth_user_id'] contains the user id of the logged user.
        if (!empty($_SESSION['auth_user_id'])) {
            $this->user->load($_SESSION['auth_user_id']);
        } else {

            // Maybe this will be handy in the future. Hooks can access this object properties via $app->auth.
            $this->app->hook('beforeAuthentication');

            // Login with empty method defaults to password-based logins.
            if ($this->slug==$this->config['login_slug'] and empty($this->method)) {
                $this->loginByPassword();

            // Login with method is passed to the Hybridauth3 third party authentication
            } elseif ($this->slug==$this->config['login_slug'] and array_key_exists($this->method, $this->config['providers']) and $this->config['providers'][$this->method]['enabled']==true) {
                $this->gotoProvider('primary', $this->method);

            // Password-less, login by email link.
            } elseif ($this->slug==$this->config['passwordless_slug']) {
                $this->loginByLink();

            // Very basic registration form.
            } elseif ($this->slug==$this->config['register_slug']) {
            
            // Catch orphan atk callbacks and redirect to login page.
            } elseif (isset($_GET['__atk_reload']) or isset($_GET['__atk_callback'])) {
                // The only code that works!
                $this->app->add(['template'=>new \atk4\ui\Template('<style>body{display: none !important;}</style><script>document.location = "' . $this->getAuthURI('login') . '";</script>')]);
                $this->app->catch_runaway_callbacks = false;
                $this->app->run();
                exit;
            }
        }
    }

    /**
     * Undocumented function
     *
     * @param [type] $target_lock
     * @return void
     */
    public function loginByPassword($target_lock='primary', $display='window')
    {
        if (!empty($_SESSION['auth_session'][$target_lock])) {
            return true;
        }

        if ($this->slug!='login' and $target_lock=='primary' and empty($_SESSION['auth_session']['primary'])) {
            $this->app->redirect($this->getAuthURI('login'));
        }

        // Create a new atk4/ui app for the login form.
        $auth_app = null;
        $this->initializeTemplate($auth_app, 'Login', $display);

        $form = $auth_app->add('Form');
        $form->buttonSave->set('Sign in');
        $form->buttonSave->addClass('large fluid green');
        $form->buttonSave->iconRight = 'right arrow';
        
        if (empty($_SESSION['auth_session']['primary'])) {
            $form->addField('email', null, ['required' => true]);
        }
        
        $form->addField('g-recaptcha-response', ['Hidden']);
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
            $social_col->addColumn()->add(['Button', 'Discord', 'discord large fluid violet', 'icon'=>'discord'])->link($this->getAuthURI('login', 'Discord'));
            $social_col->addColumn()->add(['Button', 'GitLab', 'large fluid orange', 'icon'=>'gitlab'])->link($this->getAuthURI('login', 'Amazon'));
        }

        $form->onSubmit(function ($form) use (&$auth_app, $target_lock) {
            if ($this->validRecaptcha()) {
                if (empty($_SESSION['auth_session']['primary'])) {
                    $this->user->tryLoadBy($this->config['user_email_field'], $form->model['email']);
                } else {
                    $this->user->tryLoadBy($this->config['user_id_field'], $_SESSION['auth_user_id']);
                }
                
                if ($this->user->loaded() and password_verify($form->model['password'], $this->user[$this->config['user_password_field']])) {
                    $_SESSION['auth_user_id'] = $this->user[$this->config['user_id_field']];
                    $_SESSION['auth_session'][$target_lock] = true;
                    return new \atk4\ui\jsExpression('$(".ui, div").hide();document.location = []', [$this->config['base_url'] . ($target_lock!='primary' ?  $this->getRequestURI() : '')]);
                } else {
                    return (new \atk4\ui\jsNotify('Invalid credentials.'))
                            ->setColor('red')
                            ->setPosition('topCenter')
                            ->setWidth('50')
                            ->setTransition('jiggle')
                            ->setIcon('warning sign');
                }
            } else {
                return (new \atk4\ui\jsNotify('Invalid Recaptcha.'))
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

    public function loginByLink($target_lock='primary')
    {
        if (!empty($_SESSION['auth_session'][$target_lock])) {
            return true;
        }

        $auth_app = null;
        $this->initializeTemplate($auth_app, 'Login By Link');

        $form = $auth_app->add('Form');
        $form->buttonSave->set('Send Link to Email');
        $form->buttonSave->addClass('large fluid green');
        $form->buttonSave->iconRight = 'right arrow';
        $form->addField('email', null, ['required' => true]);
        $form->addField('g-recaptcha-response', ['Hidden']);

        $form->onSubmit(function ($form) use (&$auth_app, $target_lock) {
            if ($this->validRecaptcha()) {
                if (empty($_SESSION['auth_session']['primary'])) {
                    $this->user->tryLoadBy($this->config['user_email_field'], $form->model['email']);
                } else {
                    $this->user->tryLoadBy($this->config['user_id_field'], $_SESSION['auth_user_id']);
                }
            
            
                if ($this->user->loaded()) {
                    $this->mailer($this->user[$this->config['user_email_field']], $this->config['smtp_from'], 'Login Link', "<h1>Login Link</h1><p>Heare's your login link.</p>");
                }

                return (new \atk4\ui\jsNotify('You will receive the login link to your email if this is registered in our system.'))
                ->setColor('blue')
                ->setPosition('topCenter')
                ->setWidth('50')
                ->setTransition('jiggle')
                ->setIcon('info sign');
            } else {
                return (new \atk4\ui\jsNotify('Invalid Recaptcha.'))
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

    /**
     * Undocumented function
     *
     * @param [type] $target_lock
     * @return void
     */
    public function loginBy2FA($target_lock='primary_2fa', $display='window')
    {
        if (!empty($_SESSION['auth_session'][$target_lock])) {
            return true;
        }

        if ($this->config['2fa_enabled']==2 or ($this->user[$this->config['user_enable_2fa_field']] and $this->config['2fa_enabled']==1)) {
            $ga = new \PHPGangsta_GoogleAuthenticator();
            $ga_secret = $this->user['totp_secret'];

            // Create a new atk4/ui app for the 2FA form.
            $auth_app = null;
            $this->initializeTemplate($auth_app, '2FA', $display);

            $form = $auth_app->add('Form');
            //$qrCodeUrl = $ga->getQRCodeGoogleUrl($this->app->title, $ga_secret);
            //$form->add(['template'=>new \atk4\ui\Template('<img src="' . $qrCodeUrl . '" />')]);

            $form->addField('code', '2FA Code', ['required' => true]);
            $form->addField('g-recaptcha-response', ['Hidden']);
            $form->buttonSave->set('Verify');
            $form->buttonSave->addClass('large fluid green');
            $form->buttonSave->iconRight = 'right arrow';

            $form->onSubmit(function ($form) use ($ga, $ga_secret, $target_lock) {
                if ($this->validRecaptcha()) {
                    if ($ga->verifyCode($ga_secret, $form->model['code'], 2)) {
                        $_SESSION['auth_session'][$target_lock] = true;
                        return new \atk4\ui\jsExpression('$(".ui, div").hide();document.location = []', [$this->config['base_url'] . ($target_lock!='primary_2fa' ?  $this->getRequestURI() : '')]);
                    } else {
                        return (new \atk4\ui\jsNotify('Invalid Code'))->setColor('red')
                            ->setColor('red')
                            ->setPosition('topCenter')
                            ->setWidth('50')
                            ->setTransition('jiggle')
                            ->setIcon('warning sign');
                    }
                } else {
                    return (new \atk4\ui\jsNotify('Invalid Recaptcha.'))
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

    public function loginByProvider($target_lock, $method, $display='window')
    {
        if (!empty($_SESSION['auth_session'][$target_lock])) {
            return true;
        }
        // $redirect_uri should be supplied during re-authentication calls anywhere in the atk4/ui pages.
        // The login routines above do not pass a $redirect_uri because it defaults to the $config['base_url'].
        // Also, the only way we can remember the $redirect_uri is to pass it to $_SESSION['auth_redirect']
        // so that when the callback is triggered, we can redirect the user to the appropriate pages.
        // Note that we can't attach any url redirect to the callback url because third party providers
        // usually need a constant callback url.
        $_SESSION['auth_redirect'] = $this->config['base_url'] . $this->getRequestURI();
        $_SESSION['auth_current_target'] = $target_lock;
        $this->initializeTemplate($auth_app, 'Login', $display);
        $auth_app->add('Header')->set('Login via ' . $method . ' is needed to proceed.')->addClass('center aligned');
        $auth_app->add('Button', ['Proceed', 'green fluid'])->link($this->getAuthURI('relogin', $method));
        exit;
    }

    /**
     * Undocumented function
     *
     * @param [type] $method
     * @param boolean $from_callback
     * @return void
     */
    public function gotoProvider($target_lock, $method, $from_callback = false)
    {
        if (!empty($_SESSION['auth_session'][$target_lock])) {
            return true;
        }

        $_SESSION['auth_current_method'] = $method;
        $_SESSION['auth_current_target'] = $target_lock;
        $_SESSION['auth_redirect'] = $target_lock=='primary' ? $this->config['base_url'] : $_SESSION['auth_redirect'];

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
    private function initializeTemplate(&$auth_app, $title = 'Authentication', $display='window')
    {
        if ($display=='window') {
            // Create a new atk4/ui app for the login or registration form.
            $auth_app = new \atk4\ui\App($title . ' - ' . $this->app->title);
            $this->app->catch_runaway_callbacks = false;
            $this->app->run_called = true;
            $auth_app->catch_runaway_callbacks = false;

            // Load the page template. Can be overriden by $this->config['template'].
            $auth_app->initLayout(new \atk4\ui\View(['defaultTemplate' => $this->config['template']]));
        } else {
            $auth_app = $this->app;
        }

        if ($this->config['grecaptcha_enable']) {
            $auth_app->requireJS("https://www.google.com/recaptcha/api.js?render=" . $this->config['grecaptcha_site_key']);
            $auth_app->add(['template'=>new \atk4\ui\Template("<script>grecaptcha.ready(function(){grecaptcha.execute('" . $this->config['grecaptcha_site_key'] . "',{action:'" . str_replace('.', '', $this->slug) . "'}).then(function(token) {\$('input[name=g-recaptcha-response]').val(token);});});</script><style>.grecaptcha-badge{visibility:hidden !important;}</style>")]);
        }

        // Super important!
        // atk4/ui callbacks do not know the authentication step or method for non-pretty links.
        // Without these, the callbacks will slip through the if-then-else filter below, never to be executed.
        $auth_app->stickyGet($this->config['get_auth']);
        $auth_app->stickyGet($this->config['get_method']);
        $auth_app->stickyGet($this->config['get_redirect']);
    }

    private function validRecaptcha()
    {
        $postdata = http_build_query(
            array(
                'secret' => $this->config['grecaptcha_secret_key'],
                'response' => $_POST['g-recaptcha-response']
            )
        );
        
        $opts = array('http' =>
            array(
                'method'  => 'POST',
                'header'  => 'Content-Type: application/x-www-form-urlencoded',
                'content' => $postdata
            )
        );
        
        $context  = stream_context_create($opts);
        
        return json_decode(file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, $context))->success;
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
        return $this->config['base_url'] . ($this->config['pretty_links'] ? '/' . $slug . '/' . $method : '?' . $this->config['get_auth'] . '=' . $slug . '&' . $this->config['get_method'] . '=' . $method);
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

    private function mailer($to, $from, $subject, $msg)
    {
        $transport = (new \Swift_SmtpTransport($this->config['smtp_host'], $this->config['smtp_port']))
        ->setUsername($this->config['smtp_username'])
        ->setPassword($this->config['smtp_password']);
        $mailer = new \Swift_Mailer($transport);

        $message = (new \Swift_Message($subject))
        ->setFrom($from)
        ->setTo($to)
        ->setBody(strip_tags($msg))
        ->addPart($msg, 'text/html');

        // Send the message
        $result = $mailer->send($message);
    }
}
