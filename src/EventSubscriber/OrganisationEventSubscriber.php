<?php

namespace Drupal\os2forms_nemlogin_openid_connect\EventSubscriber;

use Drupal\Component\Plugin\Exception\PluginException;
use Drupal\os2forms_organisation\Event\OrganisationUserIdEvent;
use Drupal\os2web_nemlogin\Service\AuthProviderService;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Organisation user id event subscriber.
 */
class OrganisationEventSubscriber implements EventSubscriberInterface {

  /**
   * The OS2Web Nemlogin authorization provider.
   *
   * @var \Drupal\os2web_nemlogin\Service\AuthProviderService
   */
  protected AuthProviderService $authProvider;

  /**
   * The constructor.
   */
  public function __construct(AuthProviderService $authProvider) {
    $this->authProvider = $authProvider;
  }

  /**
   * Subscribed events.
   */
  public static function getSubscribedEvents(): array {
    return [
      OrganisationUserIdEvent::class => ['setOrganisationUserId', 100],
    ];
  }

  /**
   * Attempts settings organisation user id.
   */
  public function setOrganisationUserId(OrganisationUserIdEvent $event) {
    try {
      $plugin = $this->authProvider->getActivePlugin();

      if ($plugin->isAuthenticated() && !empty($plugin->fetchValue('nameidentifier'))) {
        $event->setId($plugin->fetchValue('nameidentifier'));
      }
    }
    catch (PluginException $exception) {
      return;
    }
  }

}
