<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Helper;

use Drupal\Core\KeyValueStore\KeyValueFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreInterface;
use Drupal\os2forms_nemlogin_openid_connect\Exception\InvalidSettingException;
use Drupal\os2forms_nemlogin_openid_connect\Form\SettingsForm;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Yaml\Yaml;

/**
 * General settings for os2forms_nemlogin_openid_connect.
 */
final class Settings {
  /**
   * The store.
   *
   * @var \Drupal\Core\KeyValueStore\KeyValueStoreInterface
   */
  private KeyValueStoreInterface $store;

  /**
   * The key value collection name.
   *
   * @var string
   */
  private $collection = 'os2forms_nemlogin_openid_connect.';

  /**
   * The constructor.
   */
  public function __construct(KeyValueFactoryInterface $keyValueFactory) {
    $this->store = $keyValueFactory->get($this->collection);
  }

  /**
   * Get test mode.
   */
  public function getProviders(): string {
    return $this->get(SettingsForm::PROVIDERS, '');
  }

  /**
   * Get a setting value.
   *
   * @param string $key
   *   The key.
   * @param mixed|null $default
   *   The default value.
   *
   * @return mixed
   *   The setting value.
   */
  private function get(string $key, $default = NULL) {
    $resolver = $this->getSettingsResolver();
    if (!$resolver->isDefined($key)) {
      throw new InvalidSettingException(sprintf('Setting %s is not defined', $key));
    }

    return $this->store->get($key, $default);
  }

  /**
   * Set settings.
   *
   * @throws \Symfony\Component\OptionsResolver\Exception\ExceptionInterface
   *
   * @phpstan-param array<string, mixed> $settings
   */
  public function setSettings(array $settings): self {
    $settings = $this->getSettingsResolver()->resolve($settings);
    foreach ($settings as $key => $value) {
      $this->store->set($key, $value);
    }

    return $this;
  }

  /**
   * Get settings resolver.
   */
  private function getSettingsResolver(): OptionsResolver {
    return (new OptionsResolver())
      ->setDefaults([
        SettingsForm::PROVIDERS => '',
      ]);
  }

  /**
   * Get provider array.
   *
   * @phpstan-return array<string, mixed>
   */
  public function getProvidersAsArray(): array {
    $values = Yaml::parse($this->getProviders());

    if (empty($values) || !is_array($values)) {
      return [];
    }

    return $values;
  }

}
