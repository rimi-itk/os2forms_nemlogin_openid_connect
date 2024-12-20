<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Link;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\os2forms_nemlogin_openid_connect\Helper\Settings;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\OptionsResolver\Exception\ExceptionInterface as OptionsResolverException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * OS2Forms Nemlogin OpenID Connect settings form.
 */
final class SettingsForm extends FormBase {
  use StringTranslationTrait;

  public const PROVIDERS = 'providers';

  /**
   * The settings.
   *
   * @var \Drupal\os2forms_nemlogin_openid_connect\Helper\Settings
   */
  private Settings $settings;

  /**
   * Constructor.
   */
  public function __construct(Settings $settings) {
    $this->settings = $settings;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): SettingsForm {
    return new static(
      $container->get(Settings::class),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'os2forms_nemlogin_openid_connect_settings';
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   * @phpstan-return array<string, mixed>
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {

    $providers = $this->settings->getProviders();
    $form[self::PROVIDERS] = [
      '#type' => 'textarea',
      '#title' => $this->t('Providers'),
      '#required' => TRUE,
      '#description' => $this->t('Declare providers.<br/>Each line must be on the form <code>«id»: «label»</code>, e.g.<br/><br/><code>openid_connect_nemlogin: OpenIDConnect Nemlogin<br/>openid_connect_ad: OpenIDConnect AD</code>'),
      '#default_value' => !empty($providers) ? $providers : NULL,
    ];

    $form['actions']['#type'] = 'actions';

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save settings'),
    ];

    try {
      $providers = Yaml::parse($providers);

      $form['info'] = [
        '#type' => 'details',
        '#open' => TRUE,
        '#title' => $this->t('Provider details'),
        '#weight' => 9999,
      ];

      $form['info']['table'] = [
        '#theme' => 'table',
        '#header' => [
          ['data' => 'Id'],
          ['data' => 'Label'],
          ['data' => 'Redirect URI'],
          ['data' => ''],
        ],
        '#rows' => array_map(fn ($id, $provider) => [
          'data' => [
            ['data' => $id],
            ['data' => $provider],
            ['data' => Link::createFromRoute($provider, 'os2forms_nemlogin_openid_connect.openid_connect_authenticate', ['id' => $id])->toRenderable()],
            ['data' => Link::createFromRoute($this->t('Edit'), 'os2web_nemlogin.auth_provider.' . $id)->toRenderable()],
          ],
        ],
          array_keys($providers),
          $providers
        ),
      ];
    }
    catch (\Exception $e) {
      // Ignore all exception.
    }

    return $form;
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $providers = $form_state->getValue(self::PROVIDERS);

    try {
      $values = Yaml::parse($providers);
      if (!is_array($values)) {
        throw new ParseException('Malformed YAML');
      }
      foreach ($values as $name => $value) {
        if (!is_string($name)) {
          $form_state->setErrorByName(
            self::PROVIDERS,
            $this->t('Name (@name) must be a string; found @type.', [
              '@name' => $name,
              '@type' => gettype($name),
            ])
          );
          break;
        }
        if (!is_string($value)) {
          $form_state->setErrorByName(
            self::PROVIDERS,
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
      $form_state->setErrorByName(self::PROVIDERS, $this->t('Invalid providers (@message)', ['@message' => $exception->getMessage()]));
    }
  }

  /**
   * {@inheritdoc}
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    try {
      $settings[self::PROVIDERS] = $form_state->getValue(self::PROVIDERS);

      $this->settings->setSettings($settings);
      $this->messenger()->addStatus($this->t('Settings saved'));
    }
    catch (OptionsResolverException $exception) {
      $this->messenger()->addError($this->t('Settings not saved (@message)', ['@message' => $exception->getMessage()]));
    }

    drupal_flush_all_caches();

    $this->messenger()->addStatus($this->t('Settings saved'));
  }

}
