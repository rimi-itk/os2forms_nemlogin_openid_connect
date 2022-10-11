<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Helper;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\os2web_nemlogin\Service\AuthProviderService;
use Drupal\webform\Utility\WebformFormHelper;
use Drupal\webform\WebformInterface;
use Drupal\webform\WebformSubmissionInterface;
use Symfony\Component\Yaml\Yaml;

/**
 * Webform helper.
 */
class WebformHelper {
  use StringTranslationTrait;

  private const TEMPORARY_KEY = 'os2forms_nemlogin_openid_connect';

  /**
   * The auth provider service.
   *
   * @var \Drupal\os2web_nemlogin\Service\AuthProviderService
   */
  private AuthProviderService $authProviderService;

  /**
   * The messenger.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  private MessengerInterface $messenger;

  /**
   * Constructor.
   */
  public function __construct(AuthProviderService $authProviderService, MessengerInterface $messenger) {
    $this->authProviderService = $authProviderService;
    $this->messenger = $messenger;
  }

  /**
   * Implements hook_form_alter().
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function formAlter(array &$form, FormStateInterface $formState, string $formId): void {
    $data = $formState->getTemporaryValue(self::TEMPORARY_KEY);
    if (FALSE === ($data['access'] ?? TRUE)) {
      // Flattening the elements makes it much easier to access nested elements.
      $elements = &WebformFormHelper::flattenElements($form['elements']);

      $this->messenger->addError($this->t('Access to form denied'));

      if (isset($data['message'])) {
        $form['os2forms_nemlogin_openid_connect_message'] = [
          '#theme' => 'status_messages',
          '#message_list' => [
            'error' => [$data['message']],
          ],
        ];
      }

      // Hide all actions ….
      $form['actions']['#access'] = FALSE;
      // … and fields.
      foreach ($elements as &$element) {
        $element['#access'] = FALSE;
      }
    }
  }

  /**
   * Implements hook_ENTITY_TYPE_prepare_form().
   */
  public function webformSubmissionPrepareForm(WebformSubmissionInterface $webformSubmission, string $operation, FormStateInterface $formState): void {
    try {
      $error = $this->checkAccess($webformSubmission, $operation, $formState);

      if (NULL !== $error) {
        $webform = $webformSubmission->getWebform();
        $settings = $webform->getThirdPartySettings('os2forms')['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings'] ?? NULL;
        $message = !empty($settings['error_message']) ? $settings['error_message'] : $error;

        $formState->setTemporaryValue(self::TEMPORARY_KEY, [
          'access' => FALSE,
          'message' => $message,
        ]);
      }
    }
    catch (\Exception $exception) {
      // Only the gods know what can go wrong in the code above.
    }
  }

  /**
   * Check access.
   *
   * @return string|null
   *   Access denied message if any or null.
   */
  private function checkAccess(WebformSubmissionInterface $webformSubmission, string $operation, FormStateInterface $formState): ?string {
    $webform = $webformSubmission->getWebform();
    $settings = $webform->getThirdPartySettings('os2forms')['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings'] ?? NULL;
    // Both User claim and Form element must be set to check access.
    if (!empty($settings['user_claim']) && !empty($settings['element_key'])) {
      $elementKey = $settings['element_key'];
      $userClaim = $settings['user_claim'];

      // @todo How to handle admin users?
      $plugin = $this->authProviderService->getActivePlugin();
      if (!$plugin->isAuthenticated()) {
        return (string) $this->t('Not authenticated');
      }

      $expected = $webformSubmission->getData()[$elementKey] ?? NULL;
      if (empty($expected)) {
        return (string) $this->t('Expected value not defined');
      }

      $actual = $plugin->fetchValue($userClaim);
      if ((string) $actual !== (string) $expected) {
        return (string) $this->t('Actual value does not match expected value');
      }
    }

    // All's good!
    return NULL;
  }

  /**
   * Implements hook_webform_third_party_settings_form_alter().
   *
   * @phpstan-param array<string, mixed> $form
   */
  public function webformThirdPartySettingsFormAlter(array &$form, FormStateInterface $form_state): void {
    /** @var \Drupal\Core\Entity\EntityFormInterface $formObject */
    $formObject = $form_state->getFormObject();
    /** @var \Drupal\webform\WebformInterface $webform */
    $webform = $formObject->getEntity();
    $settings = $webform->getThirdPartySetting('os2forms', 'os2forms_nemid');

    $options = $this->getUserClaimOptions();

    $form['third_party_settings']['os2forms']['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Authentication settings'),
      '#states' => [
        'visible' => [
          [':input[name="third_party_settings[os2forms][os2forms_nemid][webform_type]"]' => ['!value' => '']],
        ],
      ],
    ];

    $form['third_party_settings']['os2forms']['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings']['user_claim'] = [
      '#type' => 'select',
      '#title' => $this->t('User claim'),
      '#default_value' => $settings['os2forms_nemlogin_openid_connect']['authentication_settings']['user_claim'] ?? NULL,
      '#empty_option' => $this->t('Not specified'),
      '#options' => $options,
      '#description' => $this->t('User data field whose value must match the value of the selected form element'),
      '#states' => [
        'required' => [
          [':input[name="third_party_settings[os2forms][os2forms_nemid][os2forms_nemlogin_openid_connect][authentication_settings][element_key]"]' => ['!value' => '']],
        ],
      ],
    ];

    $options = $this->getElementKeyOptions($webform);

    $form['third_party_settings']['os2forms']['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings']['element_key'] = [
      '#type' => 'select',
      '#title' => $this->t('Form element'),
      '#default_value' => $settings['os2forms_nemlogin_openid_connect']['authentication_settings']['element_key'] ?? NULL,
      '#empty_option' => $this->t('Not specified'),
      '#options' => $options,
      '#description' => $this->t('Form element whose value must match the value of the User data field'),
      '#states' => [
        'required' => [
          [':input[name="third_party_settings[os2forms][os2forms_nemid][os2forms_nemlogin_openid_connect][authentication_settings][user_claim]"]' => ['!value' => '']],
        ],
      ],
    ];

    $form['third_party_settings']['os2forms']['os2forms_nemid']['os2forms_nemlogin_openid_connect']['authentication_settings']['error_message'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Error message'),
      '#default_value' => $settings['os2forms_nemlogin_openid_connect']['authentication_settings']['error_message'] ?? NULL,
      '#description' => $this->t('Message to show to user if access is denied. If not set, a generic message will be shown.'),
    ];
  }

  /**
   * Get user claim options.
   *
   * @return array
   *   The user claim options.
   *
   * @phpstan-return array<string, mixed>
   */
  private function getUserClaimOptions(): array {
    $plugin = $this->authProviderService->getActivePlugin();
    $claims = $plugin->getConfiguration()['nemlogin_openid_connect_user_claims'] ?? '';

    try {
      $value = Yaml::parse($claims);
      if (is_array($value)) {
        asort($value);

        return $value;
      }
    }
    catch (\Exception $e) {
    }

    return [];
  }

  /**
   * Get element key options.
   *
   * Only simple text elements, i.e. text fields and hidden fields, are
   * returned.
   *
   * @param \Drupal\webform\WebformInterface $webform
   *   The webform.
   *
   * @return array
   *   The element key options.
   *
   * @phpstan-return array<string, mixed>
   */
  private function getElementKeyOptions(WebformInterface $webform): array {
    $elements = $webform->getElementsDecodedAndFlattened();
    $textElements = array_filter($elements, static function (array $element) {
      return in_array($element['#type'], ['textfield', 'hidden']);
    });

    return array_map(static function (array $element) {
      return $element['#title'];
    }, $textElements);
  }

}
