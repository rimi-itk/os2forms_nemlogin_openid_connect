<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Routing\LocalRedirectResponse;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\os2forms_nemlogin_openid_connect\Exception\AuthenticationException;
use Drupal\os2forms_nemlogin_openid_connect\Plugin\os2web\NemloginAuthProvider\OpenIDConnect;
use Drupal\os2web_nemlogin\Form\AuthProviderBaseSettingsForm;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Controller used for actual OpenID Connect authentication.
 */
class OpenIDConnectController implements ContainerInjectionInterface {
  use LoggerAwareTrait;
  use LoggerTrait;
  use StringTranslationTrait;

  /**
   * Session name for storing OAuth2 state.
   */
  private const SESSION_STATE = 'itkdev_openid_connect_drupal.oauth2state';

  /**
   * Session name for storing OAuth2 nonce.
   */
  private const SESSION_NONCE = 'itkdev_openid_connect_drupal.oauth2nonce';

  /**
   * Session name for storing request query parameters.
   */
  private const SESSION_REQUEST_QUERY = 'itkdev_openid_connect_drupal.request_query';

  /**
   * The config.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  private $config;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $requestStack;

  /**
   * The cache item pool.
   *
   * @var \Psr\Cache\CacheItemPoolInterface
   */
  private $cacheItemPool;

  /**
   * The plugin configuration.
   *
   * @var array
   */
  private $pluginConfiguration;

  /**
   * Constructor.
   */
  public function __construct(ConfigFactoryInterface $configFactory, RequestStack $requestStack, CacheItemPoolInterface $cacheItemPool, LoggerInterface $logger) {
    $this->config = $configFactory->get(AuthProviderBaseSettingsForm::$configName);
    $this->requestStack = $requestStack;
    $this->cacheItemPool = $cacheItemPool;
    $this->setLogger($logger);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
     $container->get('config.factory'),
     $container->get('request_stack'),
     $container->get('itkdev_openid_connect_drupal.cache_item_pool'),
     $container->get('logger.channel.os2forms_nemlogin_openid_connect')
    );
  }

  /**
   * The main controller action.
   *
   * Delegates to other functions for actual handling of requests.
   */
  public function main($plugin_id) {
    try {
      if ($configurationSerialized = $this->config->get($plugin_id)) {
        $this->pluginConfiguration = unserialize($configurationSerialized, ['allowed_classes' => FALSE]);
      }

      if (!isset($this->pluginConfiguration)) {
        throw new BadRequestHttpException(sprintf('Cannot get config for plugin %s', $plugin_id));
      }

      $request = $this->requestStack->getCurrentRequest();

      if ($request->query->has('error')) {
        return $this->displayError($request->query->get('error'), $request->query->get('error_description'));
      }

      if ($request->query->has('state')) {
        return $this->process();
      }

      return $this->start();
    }
    catch (\Exception $exception) {
      $error = $exception->getMessage();
      $description = $exception instanceof AuthenticationException ? $exception->getDescription() : NULL;
      return $this->displayError($error, $description);
    }
  }

  /**
   * Get an OpenIdConfigurationProvider instance.
   */
  private function getOpenIdConfigurationProvider(): OpenIdConfigurationProvider {
    $providerOptions = [
      'redirectUri' => Url::fromRoute(
        'itkdev_openid_connect_drupal.openid_connect',
        [
          'key' => 'nemid',
        ],
        ['absolute' => TRUE]
      )->toString(TRUE)->getGeneratedUrl(),
      'openIDConnectMetadataUrl' => $this->pluginConfiguration['nemlogin_openid_connect_discovery_url'],
      'cacheItemPool' => $this->cacheItemPool,
      'clientId' => $this->pluginConfiguration['nemlogin_openid_connect_client_id'],
      'clientSecret' => $this->pluginConfiguration['nemlogin_openid_connect_client_secret'],
    ];

    return new OpenIdConfigurationProvider($providerOptions);
  }

  /**
   * Get session.
   */
  private function getSession(): SessionInterface {
    return $this->requestStack->getCurrentRequest()->getSession();
  }

  /**
   * Set session attribute value.
   *
   * @param string $name
   *   The session attribute name.
   * @param mixed $value
   *   The session attribute value.
   */
  private function setSessionValue(string $name, $value) {
    $this->getSession()->set($name, $value);
  }

  /**
   * Get and remove session attribute value.
   *
   * By default this function removes the value from the session, but it's
   * possible to just peek at the value of need be.
   *
   * @param string $name
   *   The session attribute name.
   * @param bool $peek
   *   If set, the session value will not be removed.
   *
   * @return mixed
   *   The session value.
   */
  private function getSessionValue(string $name, bool $peek = FALSE) {
    $value = $this->getSession()->get($name);
    if (!$peek) {
      $this->getSession()->remove($name);
    }

    return $value;
  }

  /**
   * {@inheritdoc}
   */
  public function log($level, $message, array $context = []) {
    if (NULL !== $this->logger) {
      $this->logger->log($level, $message, $context);
    }
  }

  /**
   * Start OpenID Connect flow.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function start(): Response {
    $request = $this->requestStack->getCurrentRequest();
    $this->setSessionValue(self::SESSION_REQUEST_QUERY, ['query' => $request->query->all()]);

    $provider = $this->getOpenIdConfigurationProvider();
    $state = $provider->generateState();
    $nonce = $provider->generateNonce();

    $this->setSessionValue(static::SESSION_STATE, $state);
    $this->setSessionValue(static::SESSION_NONCE, $nonce);

    $authorizationUrl = $provider->getAuthorizationUrl([
      'state' => $state,
      'nonce' => $nonce,
    ]);

    $this->setSessionValue(self::SESSION_STATE, $provider->getState());

    return new TrustedRedirectResponse($authorizationUrl);
  }

  /**
   * Process OpenID Connect response.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  private function process(): Response {
    $request = $this->requestStack->getCurrentRequest();

    if (!$request->query->has('state') || !$request->query->has('id_token')) {
      $this->error('Missing state or id_token in response', ['query' => $request->query->all()]);
      throw new BadRequestHttpException('Missing state or id_token in response');
    }

    $state = $this->getSessionValue(self::SESSION_STATE);
    if ($state !== $request->query->get('state')) {
      $this->error('Invalid state', ['state' => $request->query->get('state')]);
      throw new BadRequestHttpException('Invalid state');
    }

    $provider = $this->getOpenIdConfigurationProvider();

    $token = (array) $provider->validateIdToken($request->query->get('id_token'), $this->getSessionValue(static::SESSION_NONCE));

    // Store the token for use by the authentation plugin.
    $this->getSession()->set(OpenIDConnect::SESSION_TOKEN, $token);
    $location = $this->getLoginLocation();

    return new LocalRedirectResponse($location);
  }

  /**
   * Get the location of where login flow was started.
   *
   * Fall back to the frontpage.
   *
   * @return string
   *   The login location.
   */
  private function getLoginLocation(): string {
    return $this->getSessionValue(OpenIDConnect::SESSION_LOGIN_LOCATION)
      ?? Url::fromRoute('<front>')->toString(TRUE)->getGeneratedUrl();
  }

  /**
   * Display an error.
   *
   * @return array
   *   The render array.
   */
  private function displayError(string $message, string $description = NULL): array {
    $request = $this->requestStack->getCurrentRequest();
    $this->error('Error', [
      'query' => $request->query->all(),
    ]);

    return [
      'error' => [
        '#markup' => $message,
        '#prefix' => '<h1>',
        '#suffix' => '</h1>',
      ],
      'error_description' => [
        '#markup' => $description,
        '#prefix' => '<pre>',
        '#suffix' => '</pre>',
        '#access' => NULL !== $description,
      ],
      'authenticate' => [
        '#type' => 'link',
        '#title' => $this->t('Try again'),
        '#url' => $this->getLoginLocation(),
      ],
    ];
  }

}
