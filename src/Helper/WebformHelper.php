<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Helper;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\os2web_nemlogin\Service\AuthProviderService;
use Drupal\webform\Utility\WebformFormHelper;
use Drupal\webform\WebformSubmissionInterface;

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
   */
  public function formAlter(array &$form, FormStateInterface $formState, $formId) {
    $data = $formState->getTemporaryValue(static::TEMPORARY_KEY);
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
  public function webformSubmissionPrepareForm(
    WebformSubmissionInterface $webformSubmission,
    string $operation,
    FormStateInterface $formState
  ) {
    try {
      $error = $this->checkAccess($webformSubmission, $operation, $formState);

      if (NULL !== $error) {
        $formState->setTemporaryValue(static::TEMPORARY_KEY, [
          'access' => FALSE,
          'message' => $error,
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
  private function checkAccess(WebformSubmissionInterface $webformSubmission,
    string $operation,
    FormStateInterface $formState): ?string {

    $webform = $webformSubmission->getWebform();
    $settings = $webform->getThirdPartySettings('os2forms')['os2forms_nemid']['authentication_settings'] ?? NULL;
    if (!empty($settings['actual_key']) && !empty($settings['element_key'])) {
      $expectedKey = $settings['element_key'];
      $actualKey = $settings['actual_key'];

      // @todo check for admin users.
      if (isset($expectedKey, $actualKey)) {
        $expected = $webformSubmission->getData()[$expectedKey] ?? NULL;
        if (empty($expected)) {
          return $this->t('Expected value not defined');
        }

        $plugin = $this->authProviderService->getActivePlugin();
        if (!$plugin->isAuthenticated()) {
          return $this->t('Not authenticated');
        }

        $actual = $plugin->fetchValue($actualKey);
        if ((string) $actual !== (string) $expected) {
          return $this->t('Actual value does not match expected value');
        }
      }
    }

    // All's good!
    return NULL;
  }

}
