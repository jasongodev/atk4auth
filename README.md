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
- Ability to authenticate sessions per page, specific permissions, or group of permissions. This is known as 2nd-level authentication or sudo capabilities.
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
`new Authentication(<user model or persistence model>, <config array>);`
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
To implement a 2-factor authentication, add the following code:
```php
$app->auth->loginBy2FA();
```
Note that loginBy2FA() requires a primary logged session. Therefore, you can only use it after authenticating via loginByPassword() or loginByProvider().