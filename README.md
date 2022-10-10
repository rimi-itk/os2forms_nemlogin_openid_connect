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

## Local test

When “Local test mode” in checked on
`/admin/config/system/os2web-nemlogin/OpenIDConnect`, authentication is
performed with local users defined in
`$config['os2forms_nemlogin_openid_connect']['nemlogin_openid_connect_local_test_users']`
in `settings.local.php`, e.g.

```php
// User id => user info (claims).
$config['os2forms_nemlogin_openid_connect']['nemlogin_openid_connect_local_test_users'] = [
  '1234567890' => [
    'cpr' => '1234567890',
    'name' => 'John Doe',
  ],
  'another-user' => [
    …
  ],
];
```
