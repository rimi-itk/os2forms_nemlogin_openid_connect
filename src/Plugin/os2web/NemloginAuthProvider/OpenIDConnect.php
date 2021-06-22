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
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

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
   * Identity provider URL.
   *
   * @var string
   */
  private $idpUrl;

  /**
   * Fetch only mode flag.
   *
   * @var bool
   */
  private $fetchOnce;

  /**
   * The OpenID configuration provider.
   *
   * @var \ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider
   */
  private $openIDConfigurationProvider;

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
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    // Shamelessly lifted from Drupal\os2web_nemlogin\Plugin\AuthProviderBase.
    // Swapping config with a values from config object.
    $configObject = $container->get('config.factory')->get(AuthProviderBaseSettingsForm::$configName);
    if ($configurationSerialized = $configObject->get($plugin_id)) {
      $configuration = unserialize($configurationSerialized);
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
    return $this->openIDConfigurationProvider instanceof OpenIdConfigurationProvider;
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
    if (!empty(parent::fetchValue('cpr'))) {
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
   */
  public function login() {
    $request = $this->requestStack->getCurrentRequest();

    $token = $this->getToken();
    if (NULL === $token) {
      // Pass the current request uri on the the controller to tell it where to
      // return to after authentication.
      $url = Url::fromRoute('os2forms_nemlogin_openid_connect.openid_connect_authenticate', [
        OpenIDConnectController::QUERY_LOCATION_NAME => $request->getRequestUri(),
      ])->toString();

      return (new LocalRedirectResponse($url))
        ->send();
    }

    $this->values = $token;

    return (new TrustedRedirectResponse($this->getReturnUrl()))
      ->send();
  }

  /**
   * {@inheritdoc}
   */
  public function logout() {
    $this->getToken(TRUE);

    return (new TrustedRedirectResponse($this->getReturnUrl()))
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
   */
  public function setToken(array $token): self {
    $this->session->set(static::SESSION_TOKEN, $token);

    return $this;
  }

  /**
   * Get token.
   */
  private function getToken(bool $clear = FALSE): ?array {
    $token = $this->session->get(static::SESSION_TOKEN);
    if ($clear) {
      $this->session->remove(static::SESSION_TOKEN);
    }

    return $token;
  }

  /**
   * {@inheritdoc}
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
   */
  public function defaultConfiguration() {
    return parent::defaultConfiguration() + [
      'nemlogin_openid_connect_discovery_url' => '',
      'nemlogin_openid_connect_client_id' => '',
      'nemlogin_openid_connect_client_secret' => '',
      'nemlogin_openid_connect_fetch_once' => '',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
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

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    $url = $form_state->getValue('nemlogin_openid_connect_discovery_url');

    if (!UrlHelper::isValid($url, TRUE)) {
      $form_state->setErrorByName('nemlogin_openid_connect_discovery_url', $this->t('Url is not valid'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $configuration = $this->getConfiguration();

    $configuration['nemlogin_openid_connect_discovery_url'] = $form_state->getValue('nemlogin_openid_connect_discovery_url');
    $configuration['nemlogin_openid_connect_client_id'] = $form_state->getValue('nemlogin_openid_connect_client_id');
    $configuration['nemlogin_openid_connect_client_secret'] = $form_state->getValue('nemlogin_openid_connect_client_secret');

    $this->setConfiguration($configuration);
  }

  /**
   * {@inheritdoc}
   */
  public function log($level, $message, array $context = []) {
    if (NULL !== $this->logger) {
      $this->logger->log($level, $message, $context);
    }
  }

}
