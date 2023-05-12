<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Controller;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\Routing\LocalRedirectResponse;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Site\Settings;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\os2forms_nemlogin_openid_connect\Exception\AuthenticationException;
use Drupal\os2forms_nemlogin_openid_connect\Plugin\os2web\NemloginAuthProvider\OpenIDConnect;
use Drupal\os2web_nemlogin\Service\AuthProviderService;
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
   * Session name for storing auth provider login location.
   */
  private const SESSION_LOGIN_LOCATION = 'os2forms_nemlogin_openid_connect.login_location';

  /**
   * Session name for storing OAuth2 state.
   */
  private const SESSION_STATE = 'os2forms_nemlogin_openid_connect.oauth2state';

  /**
   * Session name for storing OAuth2 nonce.
   */
  private const SESSION_NONCE = 'os2forms_nemlogin_openid_connect.oauth2nonce';

  /**
   * Session name for storing is token.
   */
  private const SESSION_ID_TOKEN = 'os2forms_nemlogin_openid_connect.id_token';

  /**
   * Name of login destination query parameter.
   *
   * Important: Must not be 'destination'!
   */
  public const QUERY_LOCATION_NAME = 'login-destination';

  /**
   * The plugin.
   *
   * @var \Drupal\os2forms_nemlogin_openid_connect\Plugin\os2web\NemloginAuthProvider\OpenIDConnect
   */
  private $plugin;

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
   * The language manager.
   *
   * @var \Drupal\Core\Language\LanguageManagerInterface
   */
  private $languageManager;

  /**
   * The cache item pool.
   *
   * @var \Psr\Cache\CacheItemPoolInterface
   */
  private $cacheItemPool;

  /**
   * The renderer.
   *
   * @var \Drupal\Core\Render\RendererInterface
   */
  private $renderer;

  /**
   * Constructor.
   */
  public function __construct(AuthProviderService $authProviderService, RequestStack $requestStack, SessionInterface $session, CacheItemPoolInterface $cacheItemPool, LanguageManagerInterface $languageManager, LoggerInterface $logger, RendererInterface $renderer) {
    $plugin = $authProviderService->getPluginInstance('OpenIDConnect');
    assert($plugin instanceof OpenIDConnect);
    $this->plugin = $plugin;

    $this->requestStack = $requestStack;
    $this->session = $session;
    $this->cacheItemPool = $cacheItemPool;
    $this->languageManager = $languageManager;
    $this->setLogger($logger);
    $this->renderer = $renderer;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new static(
      $container->get('os2web_nemlogin.auth_provider'),
      $container->get('request_stack'),
      $container->get('session'),
      $container->get('drupal_psr6_cache.cache_item_pool'),
      $container->get('language_manager'),
      $container->get('logger.channel.os2forms_nemlogin_openid_connect'),
      $container->get('renderer'),
    );
  }

  /**
   * The main controller action.
   *
   * Delegates to other functions for actual handling of requests.
   *
   * @return array|Response
   *   The renderable array or response.
   *
   * @phpstan-return array<string, mixed>|Response
   */
  public function main() {
    try {
      $request = $this->requestStack->getCurrentRequest();

      if (NULL !== ($location = $request->query->get(self::QUERY_LOCATION_NAME))) {
        $this->setLoginLocation($location);
      }

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
    $pluginConfiguration = $this->plugin->getConfiguration();

    $providerOptions = [
      'redirectUri' => $this->getRedirectUri(),
      'openIDConnectMetadataUrl' => $pluginConfiguration['nemlogin_openid_connect_discovery_url'],
      'cacheItemPool' => $this->cacheItemPool,
      'clientId' => $pluginConfiguration['nemlogin_openid_connect_client_id'],
      'clientSecret' => $pluginConfiguration['nemlogin_openid_connect_client_secret'],
      'localTestMode' => FALSE,
      'allowHttp' => (bool) ($this->getSettings()['allow_http'] ?? FALSE),
    ];

    return new OpenIdConfigurationProvider($providerOptions);
  }

  /**
   * Get redirect URI.
   */
  private function getRedirectUri(): string {
    return Url::fromRoute(
      'os2forms_nemlogin_openid_connect.openid_connect_authenticate',
      [],
      [
        'absolute' => TRUE,
        'language' => $this->languageManager->getLanguage(LanguageInterface::LANGCODE_NOT_APPLICABLE),
      ]
    )->toString(TRUE)->getGeneratedUrl();
  }

  /**
   * Set session attribute value.
   *
   * @param string $name
   *   The session attribute name.
   * @param mixed $value
   *   The session attribute value.
   *
   * @return mixed
   *   The value.
   */
  private function setSessionValue(string $name, $value) {
    return $this->session->set($name, $value);
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
    $value = $this->session->get($name);
    if (!$peek) {
      $this->session->remove($name);
    }

    return $value;
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

  /**
   * Start OpenID Connect flow.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  private function start(): Response {
    $provider = $this->getOpenIdConfigurationProvider();
    $state = $provider->generateState();
    $nonce = $provider->generateNonce();

    $this->setSessionValue(self::SESSION_STATE, $state);
    $this->setSessionValue(self::SESSION_NONCE, $nonce);

    $options = [
      'state' => $state,
      'nonce' => $nonce,
      'response_type' => 'code',
      'scope' => 'openid email profile',
    ];
    $authorizationUrl = $this->isLocalTestMode()
      ? Url::fromRoute('os2forms_nemlogin_openid_connect.openid_connect_authenticate', $options + ['test' => TRUE])->toString(TRUE)->getGeneratedUrl()
      : $provider->getAuthorizationUrl($options);

    $this->setSessionValue(self::SESSION_STATE, $provider->getState());

    return new TrustedRedirectResponse($authorizationUrl);
  }

  /**
   * End OpenID Connect session.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The response.
   */
  public function endSession(): Response {
    $provider = $this->getOpenIdConfigurationProvider();

    $postLogoutRedirectUri = $this->getPostLogoutRedirectUri();
    $endSessionUrl = $this->isLocalTestMode()
      ? $postLogoutRedirectUri
      : $provider->getEndSessionUrl($postLogoutRedirectUri, NULL, $this->getSessionValue(self::SESSION_ID_TOKEN));

    return new TrustedRedirectResponse($endSessionUrl);
  }

  /**
   * Get post logout redirect uri.
   */
  private function getPostLogoutRedirectUri(): string {
    try {
      $pluginConfiguration = $this->plugin->getConfiguration();
      $url = $pluginConfiguration['nemlogin_openid_connect_post_logout_redirect_uri'] ?? '/';
      $options = [
        'absolute' => TRUE,
        'path_processing' => FALSE,
      ];

      $url = UrlHelper::isExternal($url)
        ? Url::fromUri($url, $options)
        : Url::fromUserInput($url, $options);

      return $url->toString(TRUE)->getGeneratedUrl();
    }
    catch (\Exception $exception) {
      // Fallback if all other things fail.
      return '/';
    }
  }

  /**
   * Is local test mode?
   */
  private function isLocalTestMode(): bool {
    return (bool) ($this->getSettings()['local_test_mode'] ?? FALSE);
  }

  /**
   * Get local test users.
   *
   * @phpstan-return array<string, mixed>
   */
  private function getLocalTestUsers(): array {
    return (array) ($this->getSettings()['local_test_users'] ?? []);
  }

  /**
   * Get this module's settings.
   *
   * @phpstan-return array<string, mixed>
   */
  private function getSettings(): array {
    $settings = Settings::get('os2forms_nemlogin_openid_connect', NULL);

    return $settings ?: [];
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

    if ($this->isLocalTestMode() && (bool) $request->get('test')) {
      $users = $this->getLocalTestUsers();
      $userId = $request->get('user');
      if (isset($users[$userId])) {
        $token = $users[$userId] + ['local_test' => TRUE];
      }
      else {
        $renderable = [
          '#theme' => 'os2forms_nemlogin_openid_connect_local_test_users',
          '#users' => $users,
          '#query' => $request->query->all(),
        ];

        return new Response($this->renderer->renderPlain($renderable));
      }
    }
    else {
      if (!$request->query->has('state')) {
        $this->error('Missing state in response', ['query' => $request->query->all()]);
        throw new BadRequestHttpException('Missing state in response');
      }

      $state = $this->getSessionValue(self::SESSION_STATE);
      if ($state !== $request->query->get('state')) {
        $this->error('Invalid state', ['state' => $request->query->get('state')]);
        throw new BadRequestHttpException('Invalid state');
      }

      $provider = $this->getOpenIdConfigurationProvider();

      $idToken = match (TRUE) {
        $request->query->has('code') => $provider->getIdToken($request->query->get('code')),
        $request->query->has('id_token') => $request->query->get('id_token'),
        default => throw new BadRequestHttpException('Missing code or id_token in response')
      };

      $token = (array) $provider->validateIdToken($idToken, $this->getSessionValue(self::SESSION_NONCE));
      $this->setSessionValue(self::SESSION_ID_TOKEN, $idToken);
    }

    // Store the token for use by the authentication plugin.
    $this->plugin->setToken($token);
    $location = $this->getLoginLocation();

    return new LocalRedirectResponse($location);
  }

  /**
   * Set the location of where login flow is started.
   */
  private function setLoginLocation(string $location): self {
    $this->setSessionValue(self::SESSION_LOGIN_LOCATION, $location);

    return $this;
  }

  /**
   * Get the location of where login flow was started.
   *
   * Fall back to the frontpage.
   *
   * @return string
   *   The login location.
   */
  public function getLoginLocation(): string {
    $location = $this->getSessionValue(self::SESSION_LOGIN_LOCATION);

    return $location ?? Url::fromRoute('<front>')->toString(TRUE)->getGeneratedUrl();
  }

  /**
   * Display an error.
   *
   * @return array
   *   The render array.
   *
   * @phpstan-return array<string, mixed>
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
