<?php

declare(strict_types=1);

namespace MiGears\AclFeature\Tests;

use MiGears\AclFeature\AclFeature;
use MiGears\AclFeature\AclFeatureException;
use PHPUnit\Framework\TestCase;

/**
 * Everything the loader is strict about. Each case is one way a config can be
 * wrong, and the point of every one is the same: it fails at load time with a
 * message naming what was wrong, rather than loading a permission set that is
 * quietly not what the author wrote.
 */
final class ConfigValidationTest extends TestCase
{
    /**
     * @param array<string, mixed> $config
     */
    private function assertRejects(array $config, string $expected): void
    {
        try {
            AclFeature::fromArray($config);
            $this->fail("the config must be rejected: {$expected}");
        } catch (AclFeatureException $e) {
            $this->assertStringContainsString($expected, $e->getMessage());
        }
    }

    public function testAnUnknownTopLevelKeyIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['viewer' => ['/x' => ['GET']]], 'permissions' => []],
            "Unknown ACL feature config key 'permissions'"
        );
    }

    public function testANonBooleanDefaultIsRejected(): void
    {
        $this->assertRejects(
            ['default' => 'yes', 'roles' => ['viewer' => ['/x' => ['GET']]]],
            "key 'default' must be a bool, got string"
        );
    }

    public function testANonArrayRolesKeyIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => 'viewer'],
            "key 'roles' must be an array, got string"
        );
    }

    public function testANonArrayUsersKeyIsRejected(): void
    {
        $this->assertRejects(
            ['users' => 42],
            "key 'users' must be an array, got int"
        );
    }

    public function testNeitherRolesNorUsersIsRejected(): void
    {
        $this->assertRejects(['default' => true], 'declares neither roles nor users');
    }

    public function testAnEmptyRolesListWithNoUsersIsRejected(): void
    {
        $this->assertRejects(['roles' => []], 'declares neither roles nor users');
    }

    public function testARoleRuleMapThatIsNotAnArrayIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => 'GET /api/posts']],
            "Rules for role 'editor' must be an array of path => methods, got string"
        );
    }

    public function testAPathPatternWithoutALeadingSlashIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['api/posts' => ['GET']]]],
            "Invalid path pattern 'api/posts' for role 'editor'"
        );
    }

    public function testAPathPatternWithAMidStringWildcardIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/*/posts' => ['GET']]]],
            "Invalid path pattern '/api/*/posts' for role 'editor'"
        );
    }

    public function testAPathPatternWithATrailingSlashAfterTheWildcardIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/posts/*/' => ['GET']]]],
            "Invalid path pattern '/api/posts/*/' for role 'editor'"
        );
    }

    public function testANumericPathKeyIsRejected(): void
    {
        // PHP turns the numeric-string key into an int, so this arrives as 0
        $this->assertRejects(
            ['roles' => ['editor' => ['0' => ['GET']]]],
            "Invalid path pattern '0' for role 'editor'"
        );
    }

    public function testAnEmptyPathPatternIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['' => ['GET']]]],
            "Invalid path pattern '' for role 'editor'"
        );
    }

    public function testAMethodListThatIsNotAnArrayIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/posts' => 'GET']]],
            "Methods for path '/api/posts' of role 'editor' must be a list, got string"
        );
    }

    public function testAnEmptyMethodListIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/posts' => []]]],
            "Path '/api/posts' of role 'editor' lists no methods"
        );
    }

    public function testAnInvalidMethodNameIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/posts' => ['GE T']]]],
            "Invalid method 'GE T' for path '/api/posts' of role 'editor'"
        );
    }

    public function testAMethodThatIsNotAStringIsRejected(): void
    {
        $this->assertRejects(
            ['roles' => ['editor' => ['/api/posts' => ['GET', 42]]]],
            "Invalid method 'int' for path '/api/posts' of role 'editor'"
        );
    }

    public function testAUserEntryWithAnUnknownKeyIsRejected(): void
    {
        $this->assertRejects(
            ['users' => [42 => ['allow' => ['/api/posts' => ['GET']]]]],
            "User entry '42' accepts only 'grant' and 'deny'"
        );
    }

    public function testAUserEntryThatIsNotAnArrayIsRejected(): void
    {
        $this->assertRejects(
            ['users' => [42 => 'all']],
            "User entry '42' must be an array of grant and deny rules, got string"
        );
    }

    public function testAUserRuleMapIsValidatedLikeARoleRuleMap(): void
    {
        $this->assertRejects(
            ['users' => [42 => ['grant' => ['/api/posts' => []]]]],
            "Path '/api/posts' of user '42' grant lists no methods"
        );
    }

    /**
     * The messages name the operation as well as the user, so a bad grant and a
     * bad deny are distinguishable in a log without opening the file.
     */
    public function testAUserDenyRuleFailureNamesTheDenyOperation(): void
    {
        $this->assertRejects(
            ['users' => [42 => ['deny' => ['api/posts' => ['GET']]]]],
            "Invalid path pattern 'api/posts' for user '42' deny"
        );
    }

    // --- accepted shapes --------------------------------------------------

    public function testRolesAloneAreEnough(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['viewer' => ['/api/posts' => ['GET']]]]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
    }

    public function testUsersAloneAreEnough(): void
    {
        $acl = AclFeature::fromArray(['users' => [7 => ['grant' => ['/api/posts' => ['GET']]]]]);

        $this->assertTrue($acl->allows('GET', '/api/posts', [], 7));
    }

    public function testALowerCaseMethodIsNormalisedToUpperCase(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['viewer' => ['/api/posts' => ['get']]]]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
    }

    public function testDuplicateAndMixedCaseMethodsAreNormalised(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['viewer' => ['/api/posts' => ['get', 'GET', 'get']]]]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
        $this->assertFalse($acl->allows('POST', '/api/posts', ['viewer']));
    }

    public function testTheBareWildcardPathIsAccepted(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['root' => ['*' => ['GET']]]]);

        $this->assertTrue($acl->allows('GET', '/deeply/nested/path', ['root']));
        $this->assertFalse($acl->allows('POST', '/deeply/nested/path', ['root']));
    }

    public function testTheRootWildcardPatternIsAccepted(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['root' => ['/*' => ['GET']]]]);

        $this->assertTrue($acl->allows('GET', '/', ['root']));
        $this->assertTrue($acl->allows('GET', '/deeply/nested', ['root']));
        // '/*' requires the leading slash; it is not the bare '*' catch-all
        $this->assertFalse($acl->allows('GET', 'nested', ['root']));
        $this->assertFalse($acl->allows('POST', '/deeply/nested', ['root']));
    }

    public function testTheRootPathIsAcceptedAsAnExactPattern(): void
    {
        $acl = AclFeature::fromArray(['roles' => ['viewer' => ['/' => ['GET']]]]);

        $this->assertTrue($acl->allows('GET', '/', ['viewer']));
    }

    /**
     * A user entry naming neither operation is inert rather than an error: it
     * can only ever withhold, and withholding is already the default.
     */
    public function testAUserEntryWithNoRulesIsAcceptedAndInert(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts' => ['GET']]],
            'users' => [7 => []],
        ]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer'], 7));
        $this->assertFalse($acl->allows('DELETE', '/api/posts', ['viewer'], 7));
    }

    public function testFromArrayDoesNotMentionAFile(): void
    {
        try {
            AclFeature::fromArray(['roles' => 'viewer']);
            $this->fail('the config must be rejected.');
        } catch (AclFeatureException $e) {
            $this->assertStringNotContainsString('.php', $e->getMessage());
        }
    }
}
