<?php

declare(strict_types=1);

namespace MiGears\AclFeature;

/**
 * A request was denied, raised by assert().
 *
 * assert() is the only call that throws on a denial: allows() and denies()
 * return the answer so a caller that wants to branch keeps its control flow.
 * This extends AclFeatureException, so catching the base class catches a
 * denial and a config mistake together — which is what a caller wants at the
 * point where it would otherwise turn the denial into a 403.
 */
class DeniedException extends AclFeatureException
{
}
