<?php

declare(strict_types=1);

namespace MiGears\AclFeature;

use RuntimeException;

/**
 * An ACL feature config could not be used.
 *
 * Raised while loading: the file is missing or unreadable, it does not return
 * an array, a key is unknown, or a rule is malformed. Every one of those is an
 * assembly mistake, so it fails loudly at initialization rather than surfacing
 * later as a request that was quietly allowed or quietly denied.
 */
class AclFeatureException extends RuntimeException
{
}
