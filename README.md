# atk4auth

Atk4auth provides user authentication features to atk4/ui.
## Features
- Login by email and password.
- Login by third party authentication (Oauth 2 or OpenID).
- Supports 38 third party authentication, just set the client key and secret.
- Password-less login using login link sent to email.
- Two-factor authentication using apps that implements time-based one-time password algorithm (TOTP) like Google Authenticator and Authy.
- Two-factor authentication via SMS or email.
- Ability to chain login methods (e.g. require login by password then require 2FA). You can even annoy your users by chaining numerous login routines if you want.
- Ability to authenticate sessions per page, specific permissions, or group of permissions. This is known as 2nd-level authentication or sudo mode.
- Ability to show login and 2FA forms inline with your content or solo in a window.
- Set expiration to authenticated sessions. Expirations can be session specific or for the whole session.
- Provides a simple registration page or implement your own.
- Use your own User model or adopt our recommended User-Role-Permissions modeler (sirjasongo/atk4acl).
- Support for pretty links.
- Ability to create custom templates for login forms.
- Everything configurable, see config.php.
## Demo
soon…
## Installation
`composer require sirjasongo/atk4auth`
## Basic Usage for Primary Session
Initialize the Authentication class by adding it into the atk4/ui App object.

`new Authentication(<user model or persistence model required>, <config array optional>);`

You can either pass a user model of your own:
```php
$app = new \atk4\ui\App('My App');
$db = new \atk4\data\Persistence\SQL('mysql://user:password@localhost');
$user = new User($db);
$app->add(new Authentication($user));
```
Or pass a persistence model and let the Authentication class spawn a user model.
```php
$app = new \atk4\ui\App('My App');
$db = new \atk4\data\Persistence\SQL('mysql://user:password@localhost');
$app->add(new Authentication($db));
```
To implement a login by password on a page, place the following code:
```php
$app->auth->loginByPassword();
```
To implement a login by third party authentication ONLY (e.g. Facebook or Google), use the following:
```php
$app->auth->loginByProvider();
```
The providers that will be shown will be based on the enabled providers in the $config array that you will pass during initialization of Authentication class. By default there are no third party providers enabled.
#### Adding 2-Factor Authentication
To implement a 2-factor authentication, add the following code:
```php
$app->auth->loginBy2FA();
```
Note that loginBy2FA() requires a primary logged session. Therefore, you can only use it after authenticating via loginByPassword() or loginByProvider().

**Important:** Instruct your users to download Google Authenticator so they can generate a time-based OTP.
## Session-specific Authentication / Sudo Mode
Atk4auth can be called to authenticate a specific session, page, permission, and even groups of permissions.

This is useful when you want an extra level of security for certain pages like password reset, showing of API secret keys, or for admin level changes.
#### Use of keywords
Assuming you have a page called editprofile.php and you want to re-authenticate people who will edit their profile through this page, you can do this using any of the following code:
```php
$app->loginByPassword(__FILE__); // Shows a password form in the window.

$app->loginByPassword(__FILE__, 'window'); // Same as above

$app->loginByPassword(__FILE__, 'page'); // Shows a password form within the page.
```
The `__FILE__`  is a keyword that atk4auth will remember when a user successfully re-authenticate. The next time atk4auth encounters editprofile.php, it will check if this was re-authenticated already. If yes, it will just skip the re-authentication and proceed with the rest of your code. If not, then it will show the password form again.

Note that loginByPassword() will not show the email field during sudo mode because the user is already logged in and therefore the system knows the email already. Atk4auth just needs the password for verification.

You are free to use any keyword for re-authentication. You can use a keyword based on your own implementation of roles and permissions. Assuming you want to secure users with editor role, the following is useful:
```php
$app->auth->loginByPassword('Editor');
```
It is up to you to set the roles and permissions allowed for a certain page or content. Assuming you have a user permission called “view.logs”, you can implement a sudo mode using this:
```php
$app->auth->loginByPassword('view.logs');
```
#### Group Keywords
Atk4auth implementation based on customizable keywords allows you to make any keywords applicable to any page you set it, thus implementing a group based re-authentication.

Assuming you have editdomain.php, viewlogs.php, and billings.php that can only be viewed by the role Superadmin. Place this code in each of the three pages:
```php
$app->auth->loginByPassword('Superadmin');
```
When the user access editdomain.php and re-authenticates, the subsequent access to viewlogs.php and billings.php will not ask for the password again since atk4auth remembers the keyword ‘Superadmin’ as authenticated already.

This versatility is useful for permission-based systems. Imagine 8 pages where re-authentication is needed for the permission “access api keys”. You just need to place this code in all of the 8 pages:
```php
$app->auth->loginByPassword('access api keys');
```

Lastly, take note that you don’t even need a role-permission system in your project. If you just need to protect certain pages, the `__FILE__` magic constant is enough to protect that page. You can also declare whatever keyword to use in re-authentication.
#### Sudo Mode using 2-Factor Authentication or Third Party Provider
Just like the concept above, the re-authentication is also possible via 2FA or even a third party provider of choice:
```php
$app->auth->loginBy2FA('access api keys'); // Shows 2FA form in a window alone.

$app->auth->loginBy2FA('access api keys', 'page'); // Shows 2FA form inline with the current page. If the atk4 layout is Admin, this shows the form together with the menus.

$app->auth->loginByProvider('access api keys'); // Shows a list of enabled third party provider

$app->auth->loginByProvider('access api keys', 'Facebook'); // Shows Facebook only as a way to re-authenticate
```
#### Do not use `“primary”`and `“primary_2fa”` as keyword
By default the word `“primary”` and `“primary_2fa”` are used by atk4auth in the first level authentication. So the first login routine:
```php
$app->auth->loginByPassword();
```
is actually the same with:
```php
$app->auth->loginByPassword('primary');
```
Same is true with loginBy2FA() which uses `“primary_2fa”` and with loginByProvider which uses `“primary”` as well.
## Chaining of Authentication
You can stack as many authentication routines you want for a page. Consider the usual login routine where a password and 2FA are needed. The following code does that:
```php
$app->auth->loginByPassword();
$app->auth->loginBy2FA();
```
Atk4auth will first execute the loginByPassword(). Once authenticated via password, atk4auth will skip loginByPassword() and proceeds with loginBy2FA(). When both of these are authenticated, atk4auth will skip them and go to the rest of your code.

Assuming you have managedomain.php, addusers.php, and deleteusers.php enabled for the role “Admin”. But deleteusers.php will only be enabled for those with a special permission called “delete powers”, the following can be done:
```php
// On the top part of managedomain.php and addusers.php
// if ($user->is('Admin')){
$app->auth->loginByPassword('Admin');
// } else { echo 'Not and Admin'; }

// On the top part of deleteusers.php
// if ($user->is('Admin') and $user->can('delete powers')){
$app->auth->loginByPassword('Admin');
$app->auth->loginBy2FA('delete powers');
// } else { echo 'Not enough permission'; }

// The commented if-then-else logic is up to you to implement...
```
Wait, you might ask, “Why would someone wants to re-authenticate an admin then re-authenticates again for a certain permission? Would not this show 2 succeeding login forms like crazy? Can we not just group the keywords? Or just use the more restrictive permission “delete powers” as the sole keyword?”

Because atk4auth is not aware of the set of roles and permissions of the user model, it’s up to you to make the necessary permission checks.

There might be an instance where the above separation of authentication is useful. Assuming a company ties the 2FA OTP generator to a dedicated mobile device only located in the company’s 3-tier secure premises. An admin who accesses the dashboard in a middle of a beer pong party, very drunk, will not be able to use its delete powers despite able to login as an admin because the mobile device that can generate the OTP codes is in the office.

Now imagine a nuclear missile launch that uses atk4/ui and atk4auth codes for their dashboard. Atk4auth’s versatility saves the world.
## Expiration of Authentication
## Configuration
A sample of the $config array is in the config.php. If you implement your own Users model and have assigned custom fields for the fields that atk4auth uses for authentication, you can indicate the custom fields in the configuration.

Perhaps you will spend most of your time configuring the third party provider which needs to have a client key and secret. You may also change the color of the button using the CSS class color. Atk4auth just like atk4/ui uses Fomantic UI for styling.

**Important:** Do not change the primary handle name of the third party provider (e.g. Facebook or Google) because these are directly used by atk4auth in identifying the correct third party endpoints. Do not change it from Facebook to “FB” or “FB Login”. Doing so will break the functionality.