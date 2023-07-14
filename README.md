# OS2Forms NemLogin OpenID Connect

Implements an [OS2Web NemLog-in
`AuthProvider`](https://github.com/OS2web/os2web_nemlogin/blob/master/src/Annotation/AuthProvider.php),
[`OpenIDConnect`](src/Plugin/os2web/NemloginAuthProvider/OpenIDConnect.php), for
authenticating with [OpenID Connect](https://openid.net/connect/).

A controller,
[`OpenIDConnectController`](src/Controller/OpenIDConnectController.php), takes
care of the actual NemLog-in authenticating.

## Installation

```sh
composer require itk-dev/os2forms_nemlogin_openid_connect
vendor/bin/drush pm:enable os2forms_nemlogin_openid_connect
```

## Configuration

Go to `/admin/config/system/os2web-nemlogin/OpenIDConnect` to set up the OpenID
Connect configuration.

Enable “OpenIDConnect Nemlogin auth provider” on
`/admin/config/system/os2web-nemlogin`.

## Use on a webform

Edit a webform, go to Settings > Third Party Settings > OS2Forms > OS2Forms NemID
settings and specify “Webform type”:

![Webform type](docs/assets/Webform-type.png)

## Authentication settings

When “Webform type” is specified it’s possible to add an authentication check on
the form by requiring the value of a field (pre-filled with a value from a
previous submission) to match the value of a specified user property.

Before using authentication checks, “User claims” available for the checks must
be defined on `/admin/config/system/os2web-nemlogin/OpenIDConnect`.

Edit a webform, go to Settings > Third Party Settings > OS2Forms > OS2Forms
NemID settings > Authentication settings and define which “User claim” value
must match a “Form element” value:

![Authentication settings](docs/assets/authentication-settings.png)

Note: The authentication check sits on top of the other access checks in
OS2Forms, i.e. it does not itself grant access, but adds additonal requirements
that must be fulfilled before a user can fill in a form.

## Local test

Authenticating with local test users can be enabled in `settings.local.php`:

```php
// Enable local test mode
$settings['os2forms_nemlogin_openid_connect']['local_test_mode'] = TRUE;

// Define local test users
//   User id => user info (claims)
$settings['os2forms_nemlogin_openid_connect']['local_test_users'] = [
  '1234567890' => [
    'cpr' => '1234567890',
    'name' => 'John Doe',
  ],
  'another-user' => [
    …
  ],
];

// Override settings for specific plugins:
$settings['os2forms_nemlogin_openid_connect']['my-plugin-id']['local_test_mode'] = FALSE;

// Define local test users
//   User id => user info (claims)
$settings['os2forms_nemlogin_openid_connect']['another-plugin-id']['local_test_users'] = [
  'user087' => [
    'id' => 'user087',
    'name' => 'User 87',
  ],
];

```
