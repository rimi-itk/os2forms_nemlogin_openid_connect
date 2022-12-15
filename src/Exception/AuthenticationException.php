<?php

namespace Drupal\os2forms_nemlogin_openid_connect\Exception;

/**
 * Authentication exception.
 */
class AuthenticationException extends \RuntimeException {
  /**
   * The error description.
   *
   * @var string
   */
  private $description;

  /**
   * Set description.
   */
  public function setDescription(string $description): self {
    $this->description = $description;

    return $this;
  }

  /**
   * Get description.
   */
  public function getDescription(): ?string {
    return $this->description;
  }

}
