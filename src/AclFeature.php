<?php

declare(strict_types=1);

namespace MiGears\AclFeature;

/**
 * Endpoint-level access control, decided from a PHP config file.
 *
 * The question is "may this subject call this endpoint?", and the rules are
 * keyed by URL path and HTTP method — the same pair the router already uses.
 * That is the point: there is no second vocabulary of permission names to
 * invent, keep in step with the routes, and re-check on every rename.
 *
 *   // config/acl-feature.php — application root, beside src/ and tests/
 *   return [
 *       'default' => false,                       // unmatched requests are denied
 *       'roles' => [
 *           'admin'  => ['*' => ['*']],
 *           'editor' => [
 *               '/api/posts'   => ['GET', 'POST'],
 *               '/api/posts/*' => ['GET', 'PUT'],
 *           ],
 *       ],
 *       'users' => [
 *           42 => ['grant' => ['/api/billing/*' => ['GET']]],
 *       ],
 *   ];
 *
 *   $acl = AclFeature::fromFile(__DIR__ . '/config/acl-feature.php');
 *   $acl->assert('POST', '/api/posts', ['editor'], 42);
 *
 * The recommended call site is MiRest::before(), so the check finishes before
 * the request reaches a resource handler: a denial then short-circuits the
 * pipeline and no handler code runs at all.
 *
 * What this is not: no database, no session, no container, no HTTP types. One
 * file is read at load time and the decision is made from memory afterwards,
 * so allows() is a pure function of the config and its arguments. Which rows a
 * caller may reach, and which columns of a row, are other modules' questions.
 */
final class AclFeature
{
    public const VERSION = '2.0.0';

    /** @var array<string, array<string, list<string>>> role => path pattern => methods */
    private array $roles;

    /** @var array<string, array<string, array<string, list<string>>>> userId => grant|deny => path pattern => methods */
    private array $users;

    private bool $default;

    private int|string|null $userId;

    /**
     * @param array<string, array<string, list<string>>>                 $roles
     * @param array<string, array<string, array<string, list<string>>>>  $users
     */
    private function __construct(bool $default, array $roles, array $users, int|string|null $userId)
    {
        $this->default = $default;
        $this->roles = $roles;
        $this->users = $users;
        $this->userId = $userId;
    }

    /**
     * Read and validate a config file.
     *
     * The whole file is validated before an instance exists, so a config with
     * one bad entry loads nothing at all: like the rest of the framework's
     * assembly, this is all-or-nothing rather than half-accepted.
     *
     * @throws AclFeatureException when the file is missing or unreadable, does
     *                             not return an array, or holds a bad entry
     */
    public static function fromFile(string $file): self
    {
        if (!is_file($file) || !is_readable($file)) {
            throw new AclFeatureException("ACL feature config not found or not readable: {$file}");
        }

        $config = require $file;

        if (!is_array($config)) {
            throw new AclFeatureException(
                'ACL feature config must return an array, got ' . get_debug_type($config) . ": {$file}"
            );
        }

        return self::build($config, $file);
    }

    /**
     * Build from an already-loaded config array — for tests, and for a
     * composition root that assembles the array itself.
     *
     * @param array<string, mixed> $config
     *
     * @throws AclFeatureException when the config holds a bad entry
     */
    public static function fromArray(array $config): self
    {
        return self::build($config, null);
    }

    /**
     * Decide for one subject on one request.
     *
     * The order is fixed rather than resolved by precedence, so an overlapping
     * deny and grant are never silently collapsed into one of them:
     *
     *   1. start from `default` (false when omitted)
     *   2. any role whose rule map matches the request grants it
     *   3. a user-level deny returns false outright, else a user-level grant
     *      returns true
     *   4. otherwise the result so far stands
     *
     * @param string|list<string> $roles
     */
    public function allows(
        string $method,
        string $path,
        string|array $roles,
        int|string|null $userId = null,
    ): bool {
        $method = strtoupper($method);
        $userId ??= $this->userId;

        $allowed = $this->default;

        foreach (self::roleList($roles) as $role) {
            if (isset($this->roles[$role]) && self::matches($this->roles[$role], $method, $path)) {
                $allowed = true;
                break;
            }
        }

        if ($userId !== null) {
            $entry = $this->users[(string) $userId] ?? [];

            if (self::matches($entry['deny'] ?? [], $method, $path)) {
                return false;
            }

            if (self::matches($entry['grant'] ?? [], $method, $path)) {
                return true;
            }
        }

        return $allowed;
    }

    /**
     * The negation of allows(), for callers that find it reads better.
     *
     * @param string|list<string> $roles
     */
    public function denies(
        string $method,
        string $path,
        string|array $roles,
        int|string|null $userId = null,
    ): bool {
        return !$this->allows($method, $path, $roles, $userId);
    }

    /**
     * A semantic alias of allows() for the request-shaped call site: it reads
     * as "decide for this request", which is what MiRest::before() is doing.
     *
     * @param string|list<string> $roles
     */
    public function forRequest(
        string $method,
        string $path,
        string|array $roles,
        int|string|null $userId = null,
    ): bool {
        return $this->allows($method, $path, $roles, $userId);
    }

    /**
     * Throw unless the request is allowed.
     *
     * @param string|list<string> $roles
     *
     * @throws DeniedException when the request is not allowed
     */
    public function assert(
        string $method,
        string $path,
        string|array $roles,
        int|string|null $userId = null,
    ): void {
        if ($this->allows($method, $path, $roles, $userId)) {
            return;
        }

        throw new DeniedException(sprintf(
            '%s %s denied for roles [%s]',
            strtoupper($method),
            $path,
            implode(', ', self::roleList($roles))
        ));
    }

    /**
     * A copy bound to one subject, for call sites that would otherwise carry
     * the user id through every call. The instance it came from is untouched.
     */
    public function withUser(int|string $userId): self
    {
        return new self($this->default, $this->roles, $this->users, $userId);
    }

    /**
     * Validate the whole config and compile it into its lookup shape.
     *
     * `$source` is the file the config came from, or null for fromArray(); it
     * is appended to every load-time message, so a file config names the file
     * and an array config stays quiet about a file it does not have.
     *
     * @param array<string, mixed> $config
     *
     * @throws AclFeatureException
     */
    private static function build(array $config, ?string $source): self
    {
        $where = $source === null ? '' : ": {$source}";

        foreach (array_keys($config) as $key) {
            if (!in_array($key, ['default', 'roles', 'users'], true)) {
                throw new AclFeatureException("Unknown ACL feature config key '{$key}'{$where}");
            }
        }

        $default = $config['default'] ?? false;
        if (!is_bool($default)) {
            throw new AclFeatureException(
                "ACL feature config key 'default' must be a bool, got " . get_debug_type($default) . $where
            );
        }

        $roles = [];
        if (array_key_exists('roles', $config)) {
            if (!is_array($config['roles'])) {
                throw new AclFeatureException(
                    "ACL feature config key 'roles' must be an array, got "
                    . get_debug_type($config['roles']) . $where
                );
            }

            foreach ($config['roles'] as $role => $rules) {
                $name = (string) $role;
                $roles[$name] = self::rules($rules, "role '{$name}'", $where);
            }
        }

        $users = [];
        if (array_key_exists('users', $config)) {
            if (!is_array($config['users'])) {
                throw new AclFeatureException(
                    "ACL feature config key 'users' must be an array, got "
                    . get_debug_type($config['users']) . $where
                );
            }

            foreach ($config['users'] as $id => $entry) {
                $name = (string) $id;

                if (!is_array($entry)) {
                    throw new AclFeatureException(
                        "User entry '{$name}' must be an array of grant and deny rules, got "
                        . get_debug_type($entry) . $where
                    );
                }

                foreach (array_keys($entry) as $key) {
                    if (!in_array($key, ['grant', 'deny'], true)) {
                        throw new AclFeatureException(
                            "User entry '{$name}' accepts only 'grant' and 'deny'{$where}"
                        );
                    }
                }

                $user = [];
                foreach (['grant', 'deny'] as $operation) {
                    if (array_key_exists($operation, $entry)) {
                        $user[$operation] = self::rules(
                            $entry[$operation],
                            "user '{$name}' {$operation}",
                            $where
                        );
                    }
                }

                $users[$name] = $user;
            }
        }

        if ($roles === [] && $users === []) {
            throw new AclFeatureException("ACL feature config declares neither roles nor users{$where}");
        }

        return new self($default, $roles, $users, null);
    }

    /**
     * Validate one path-rule map — the shape a role and a user's grant/deny
     * halves all share: path pattern => list of method patterns.
     *
     * @return array<string, list<string>>
     *
     * @throws AclFeatureException
     */
    private static function rules(mixed $map, string $owner, string $where): array
    {
        if (!is_array($map)) {
            throw new AclFeatureException(
                "Rules for {$owner} must be an array of path => methods, got " . get_debug_type($map) . $where
            );
        }

        $rules = [];

        foreach ($map as $pattern => $methods) {
            if (!is_string($pattern) || !self::isPathPattern($pattern)) {
                $shown = is_string($pattern) ? $pattern : (string) $pattern;
                throw new AclFeatureException("Invalid path pattern '{$shown}' for {$owner}{$where}");
            }

            if (!is_array($methods)) {
                throw new AclFeatureException(
                    "Methods for path '{$pattern}' of {$owner} must be a list, got "
                    . get_debug_type($methods) . $where
                );
            }

            if ($methods === []) {
                throw new AclFeatureException("Path '{$pattern}' of {$owner} lists no methods{$where}");
            }

            // Deduplicate while normalising, so the stored set is exactly the
            // methods this path allows and nothing more.
            $normalised = [];
            foreach ($methods as $method) {
                if (!is_string($method) || !self::isMethodPattern($method)) {
                    $shown = is_string($method) ? $method : get_debug_type($method);
                    throw new AclFeatureException(
                        "Invalid method '{$shown}' for path '{$pattern}' of {$owner}{$where}"
                    );
                }

                $normalised[strtoupper($method)] = true;
            }

            $rules[$pattern] = array_keys($normalised);
        }

        return $rules;
    }

    /**
     * A path pattern is `*`, an exact path beginning with `/`, or a prefix
     * ending in `/*` which also matches the prefix itself.
     *
     * The single `*` is the whole grammar. There is no `:param` and no
     * mid-string wildcard, because route parameters belong to the router and
     * gating on a specific id is acl-data's job — a permission that depends on
     * which row is being addressed is not an endpoint permission.
     */
    private static function isPathPattern(string $pattern): bool
    {
        if ($pattern === '*') {
            return true;
        }

        if ($pattern === '' || $pattern[0] !== '/') {
            return false;
        }

        $stars = substr_count($pattern, '*');

        return $stars === 0 || ($stars === 1 && str_ends_with($pattern, '/*'));
    }

    /**
     * A method pattern is `*` or an HTTP method token. Comparison is
     * case-insensitive, and the stored form is upper case.
     */
    private static function isMethodPattern(string $method): bool
    {
        return $method === '*' || preg_match('/^[A-Za-z][A-Za-z0-9_-]*$/', $method) === 1;
    }

    /**
     * True when any pattern in the map matches the request.
     *
     * @param array<string, list<string>> $rules
     */
    private static function matches(array $rules, string $method, string $path): bool
    {
        foreach ($rules as $pattern => $methods) {
            if (!self::matchesPath($pattern, $path)) {
                continue;
            }

            foreach ($methods as $candidate) {
                if ($candidate === '*' || $candidate === $method) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * `/api/posts/*` matches the prefix itself and anything under it, with the
     * boundary on a segment: `/api/posts/42` is under `/api/posts`, and
     * `/api/postscript` is not.
     */
    private static function matchesPath(string $pattern, string $path): bool
    {
        if ($pattern === '*') {
            return true;
        }

        if (!str_ends_with($pattern, '/*')) {
            return $pattern === $path;
        }

        $prefix = substr($pattern, 0, -2);

        return $path === $prefix || str_starts_with($path, $prefix . '/');
    }

    /**
     * Normalise the roles argument to a list of strings.
     *
     * The type hint only promises `array`; the elements are whatever the
     * caller passed. A non-scalar role is rendered as its type name instead of
     * raising, so a malformed argument denies rather than breaking the request
     * — the same posture as an unknown role.
     *
     * @param string|array<array-key, mixed> $roles
     *
     * @return list<string>
     */
    private static function roleList(string|array $roles): array
    {
        return array_map(
            static fn (mixed $role): string => is_scalar($role) ? (string) $role : get_debug_type($role),
            array_values((array) $roles)
        );
    }
}
