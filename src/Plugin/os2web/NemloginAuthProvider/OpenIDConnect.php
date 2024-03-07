<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Plugin\os2web\NemloginAuthProvider;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Routing\LocalRedirectResponse;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\os2forms_nemlogin_openid_connect\Controller\OpenIDConnectController;
use Drupal\os2web_nemlogin\Form\AuthProviderBaseSettingsForm;
use Drupal\os2web_nemlogin\Plugin\AuthProviderBase;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Defines a plugin for Nemlogin auth via OpenID Connect.
 *
 * @AuthProvider(
 *   id = "OpenIDConnect",
 *   label = @Translation("OpenIDConnect Nemlogin auth provider"),
 * )
 */
class OpenIDConnect extends AuthProviderBase {
  use LoggerTrait;
  use LoggerAwareTrait;

  /**
   * Session name for storing OIDC user token.
   */
  private const SESSION_TOKEN = 'os2forms_nemlogin_openid_connect.user_token';

  /**
   * Fetch only mode flag.
   *
   * @var bool
   */
  private $fetchOnce = FALSE;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $requestStack;

  /**
   * The session.
   *
   * @var \Symfony\Component\HttpFoundation\Session\SessionInterface
   */
  private $session;

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $configuration
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, RequestStack $requestStack, SessionInterface $session, LoggerInterface $logger) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $this->session = $session;
    $this->requestStack = $requestStack;
    $this->setLogger($logger);

    $this->values = $this->getToken() ?? [];
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $configuration
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    // Shamelessly lifted from Drupal\os2web_nemlogin\Plugin\AuthProviderBase.
    // Swapping config with a values from config object.
    $configObject = $container->get('config.factory')->get(AuthProviderBaseSettingsForm::$configName);
    if ($configurationSerialized = $configObject->get($plugin_id)) {
      $configuration = unserialize($configurationSerialized, ['allowed_classes' => FALSE]);
    }
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('request_stack'),
      $container->get('session'),
      $container->get('logger.channel.os2forms_nemlogin_openid_connect')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function isInitialized() {
    $configuration = $configuration = $this->getConfiguration();
    if (!empty($configuration['nemlogin_openid_connect_discovery_url'])) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function isAuthenticated() {
    // If user has any authenticated data consider it as authenticated.
    return !empty($this->values);
  }

  /**
   * {@inheritdoc}
   */
  public function isAuthenticatedPerson() {
    // We have to fetch value via parent, in order to avoid possible deletion
    // of value if "fetchOnce" flag is TRUE.
    // It's important that CVR key is empty, since
    // users often login on behalf of company as themselves
    // i.e. values may contain both a cpr and cvr value.
    if (!empty(parent::fetchValue('cpr')) && empty(parent::fetchValue('cvr'))) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function isAuthenticatedCompany() {
    // We have to fetch value via parent, in order to avoid possible deletion
    // of value if "fetchOnce" flag is TRUE.
    if (!empty(parent::fetchValue('cvr'))) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  public function login() {
    $request = $this->requestStack->getCurrentRequest();

    $token = $this->getToken();
    if (NULL === $token) {
      // Pass the current request uri on to the controller to tell it where to
      // return to after authentication.
      $url = Url::fromRoute('os2forms_nemlogin_openid_connect.openid_connect_authenticate', [
        'id' => $this->getPluginId(),
        OpenIDConnectController::QUERY_LOCATION_NAME => $request->getRequestUri(),
      ])
        ->toString(TRUE)
        ->getGeneratedUrl();

      return (new LocalRedirectResponse($url))
        ->send();
    }

    $this->values = $token;

    return (new TrustedRedirectResponse($this->getReturnUrl()))
      ->send();
  }

  /**
   * {@inheritdoc}
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  public function logout() {
    $this->getToken(TRUE);
    $this->values = [];

    $url = Url::fromRoute('os2forms_nemlogin_openid_connect.openid_connect_end_session', [
      'id' => $this->getPluginId(),
    ])
      ->toString(TRUE)
      ->getGeneratedUrl();

    return (new TrustedRedirectResponse($url))
      ->send();
  }

  /**
   * Set token.
   *
   * Used by authentication controller to set the result of the actual user
   * authentication.
   *
   * @param array $token
   *   The user token.
   *
   * @return $this
   *
   * @phpstan-param array<string, mixed> $token
   */
  public function setToken(array $token): self {
    $this->session->set(self::SESSION_TOKEN, $token);

    return $this;
  }

  /**
   * Get token.
   *
   * @phpstan-return array<string, mixed>|null
   */
  private function getToken(bool $clear = FALSE): ?array {
    $token = $this->session->get(self::SESSION_TOKEN);
    if ($clear) {
      $this->session->remove(self::SESSION_TOKEN);
    }

    return $token;
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param string|array<string, mixed> $key
   */
  public function fetchValue($key) {
    $value = parent::fetchValue($key);

    // @todo handle this
    if ($this->fetchOnce) {
      unset($this->values[$key]);
    }
    return $value;
  }

  /**
   * {@inheritdoc}
   *
   * @return array
   *   The default configuration.
   *
   * @phpstan-return array<string, mixed>
   */
  public function defaultConfiguration() {
    return parent::defaultConfiguration() + [
      'nemlogin_openid_connect_discovery_url' => '',
      'nemlogin_openid_connect_client_id' => '',
      'nemlogin_openid_connect_client_secret' => '',
      'nemlogin_openid_connect_fetch_once' => '',
      'nemlogin_openid_connect_post_logout_redirect_uri' => '',
      'nemlogin_openid_connect_user_claims' => '',
    ];
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   * @phpstan-return array<string, mixed>
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state): array {
    $form['nemlogin_openid_connect_discovery_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('OpenID Connect Discovery url'),
      // Our urls are very long.
      '#maxlength' => 256,
      '#required' => TRUE,
      '#default_value' => $this->configuration['nemlogin_openid_connect_discovery_url'] ?? NULL,
      '#description' => $this->t('OpenID Connect Discovery url (cf. <a href="https://swagger.io/docs/specification/authentication/openid-connect-discovery/">https://swagger.io/docs/specification/authentication/openid-connect-discovery/</a>)'),
    ];
    $form['nemlogin_openid_connect_client_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client id'),
      '#required' => TRUE,
      '#default_value' => $this->configuration['nemlogin_openid_connect_client_id'] ?? NULL,
    ];
    $form['nemlogin_openid_connect_client_secret'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client secret'),
      '#required' => TRUE,
      '#default_value' => $this->configuration['nemlogin_openid_connect_client_secret'] ?? NULL,
    ];
    $form['nemlogin_openid_connect_fetch_once'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Use fetch only mode.'),
      '#default_value' => $this->configuration['nemlogin_openid_connect_fetch_once'] ?? FALSE,
      '#description' => $this->t('User will be logged out immediately after login. User data will be removed from session after first retrieving'),
    ];

    $form['nemlogin_openid_connect_post_logout_redirect_uri'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Post logout redirect url'),
      '#required' => TRUE,
      '#default_value' => $this->configuration['nemlogin_openid_connect_post_logout_redirect_uri'] ?? NULL,
      '#description' => $this->t('Url to redirect to after logout. Can be an internal path, e.g. <code>/node/87</code>, or an external url, e.g. <code>https://aarhus.dk</code>'),
    ];

    $form['nemlogin_openid_connect_user_claims'] = [
      '#type' => 'textarea',
      '#title' => $this->t('User claims'),
      '#description' => $this->t('Describe user claims for use when comparing user values.<br/>Each line must be on the form <code>«claim»: «display name»</code>, e.g.<br/><br/><code>cpr: CPR-nummer<br/>email: E-mailadresse</code>'),
      '#default_value' => $this->configuration['nemlogin_openid_connect_user_claims'] ?? NULL,
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state): void {
    $url = $form_state->getValue('nemlogin_openid_connect_discovery_url');

    if (!UrlHelper::isValid($url, TRUE)) {
      $form_state->setErrorByName('nemlogin_openid_connect_discovery_url', $this->t('Url is not valid'));
    }

    $url = $form_state->getValue('nemlogin_openid_connect_post_logout_redirect_uri');
    try {
      UrlHelper::isExternal($url) ? Url::fromUri($url) : Url::fromUserInput($url);
    }
    catch (\Exception $exception) {
      $form_state->setErrorByName('nemlogin_openid_connect_post_logout_redirect_uri', $this->t('Post logout redirect url is not valid (@message)', ['@message' => $exception->getMessage()]));
    }

    $claims = $form_state->getValue('nemlogin_openid_connect_user_claims');
    try {
      $values = Yaml::parse($claims);
      foreach ($values as $name => $value) {
        if (!is_string($name)) {
          $form_state->setErrorByName(
            'nemlogin_openid_connect_user_claims',
            $this->t('Name (@name) must be a string; found @type.', [
              '@name' => $name,
              '@type' => gettype($name),
            ])
          );
          break;
        }
        if (!is_string($value)) {
          $form_state->setErrorByName(
            'nemlogin_openid_connect_user_claims',
            $this->t('Value for “@name” must be a string; found @type.', [
              '@name' => $name,
              '@type' => gettype($value),
            ])
          );
          break;
        }
      }
    }
    catch (ParseException $exception) {
      $form_state->setErrorByName('nemlogin_openid_connect_user_claims', $this->t('Invalid claims (@message)', ['@message' => $exception->getMessage()]));
    }
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state): void {
    $configuration = $this->getConfiguration();

    $configuration['nemlogin_openid_connect_discovery_url'] = $form_state->getValue('nemlogin_openid_connect_discovery_url');
    $configuration['nemlogin_openid_connect_client_id'] = $form_state->getValue('nemlogin_openid_connect_client_id');
    $configuration['nemlogin_openid_connect_client_secret'] = $form_state->getValue('nemlogin_openid_connect_client_secret');
    $configuration['nemlogin_openid_connect_fetch_once'] = $form_state->getValue('nemlogin_openid_connect_fetch_once');
    $configuration['nemlogin_openid_connect_post_logout_redirect_uri'] = $form_state->getValue('nemlogin_openid_connect_post_logout_redirect_uri');
    $configuration['nemlogin_openid_connect_user_claims'] = $form_state->getValue('nemlogin_openid_connect_user_claims');

    $this->setConfiguration($configuration);
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param mixed $level
   * @phpstan-param string $message
   * @phpstan-param array<string, mixed> $context
   */
  public function log($level, $message, array $context = []): void {
    if (NULL !== $this->logger) {
      $this->logger->log($level, $message, $context);
    }
  }

}
