<?php

declare(strict_types=1);

namespace MiGears\AclFeature\Tests;

use MiGears\AclFeature\AclFeature;
use MiGears\AclFeature\AclFeatureException;
use MiGears\AclFeature\DeniedException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AclFeatureTest extends TestCase
{
    private string $config;

    protected function setUp(): void
    {
        $this->config = __DIR__ . '/Fixtures/config';
    }

    /**
     * The shape used by most tests: two roles with different reach, a catch-all
     * role, and one user carrying both a grant and a deny.
     *
     * @return array<string, mixed>
     */
    private function config(): array
    {
        return [
            'default' => false,
            'roles' => [
                'admin' => ['*' => ['*']],
                'editor' => [
                    '/api/posts' => ['GET', 'POST'],
                    '/api/posts/*' => ['GET', 'PUT'],
                ],
                'viewer' => [
                    '/api/posts' => ['GET'],
                    '/api/posts/*' => ['GET'],
                ],
            ],
            'users' => [
                42 => [
                    'grant' => ['/api/billing/*' => ['GET']],
                    'deny' => [
                        '/api/posts' => ['POST'],
                        '/api/posts/*' => ['DELETE'],
                    ],
                ],
            ],
        ];
    }

    private function acl(): AclFeature
    {
        return AclFeature::fromArray($this->config());
    }

    // --- matching ---------------------------------------------------------

    public function testItDeniesWhenNothingMatches(): void
    {
        $this->assertFalse($this->acl()->allows('GET', '/api/unknown', ['viewer']));
    }

    public function testARoleGrantsThePathAndMethodItLists(): void
    {
        $this->assertTrue($this->acl()->allows('GET', '/api/posts', ['editor']));
        $this->assertTrue($this->acl()->allows('POST', '/api/posts', ['editor']));
    }

    public function testARoleDoesNotGrantAMethodItDoesNotList(): void
    {
        $this->assertFalse($this->acl()->allows('DELETE', '/api/posts', ['editor']));
    }

    public function testACatchAllRoleGrantsEverything(): void
    {
        $acl = $this->acl();

        $this->assertTrue($acl->allows('DELETE', '/anything/at/all', ['admin']));
        $this->assertTrue($acl->allows('GET', '/', ['admin']));
    }

    public function testAPathPrefixMatchesThePrefixItself(): void
    {
        // '/api/posts/*' is documented to cover '/api/posts' too
        $this->assertTrue($this->acl()->allows('PUT', '/api/posts', ['editor']));
    }

    public function testAPathPrefixMatchesDescendants(): void
    {
        $acl = $this->acl();

        $this->assertTrue($acl->allows('GET', '/api/posts/42', ['viewer']));
        $this->assertTrue($acl->allows('GET', '/api/posts/42/comments', ['viewer']));
    }

    public function testAPathPrefixStopsAtTheSegmentBoundary(): void
    {
        // '/api/postscript' is not under '/api/posts'
        $this->assertFalse($this->acl()->allows('GET', '/api/postscript', ['viewer']));
    }

    public function testAnExactPatternMatchesOnlyItself(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts' => ['GET']]],
        ]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/posts/42', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/posts/', ['viewer']));
    }

    /**
     * A `*` that is not the last segment covers exactly one segment, so an
     * endpoint whose path carries an id in the middle is still nameable on its
     * own — the comments of one post, rather than the post or a comment's own
     * children.
     */
    public function testAMiddleWildcardCoversExactlyOneSegment(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts/*/comments' => ['GET']]],
        ]);

        $this->assertTrue($acl->allows('GET', '/api/posts/42/comments', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/posts/42', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/posts/42/comments/7', ['viewer']));
    }

    /**
     * Several wildcard segments can be nested. The trailing one keeps its
     * subtree meaning, so the rule covers the head it hangs off as well as
     * everything under that head.
     */
    public function testSeveralWildcardSegmentsCanBeNested(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts/*/comments/*' => ['DELETE']]],
        ]);

        $this->assertTrue($acl->allows('DELETE', '/api/posts/42/comments/7', ['viewer']));
        // the head is the comments collection, and the prefix form includes it
        $this->assertTrue($acl->allows('DELETE', '/api/posts/42/comments', ['viewer']));
        $this->assertFalse($acl->allows('DELETE', '/api/posts/42', ['viewer']));
    }

    public function testAMiddleWildcardStopsAtItsOwnDepthOnly(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts/*/comments' => ['GET']]],
        ]);

        // the boundary is still a segment on either side of the wildcard
        $this->assertFalse($acl->allows('GET', '/api/posts/comments', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/posts/42/commentary', ['viewer']));
    }

    public function testATrailingWildcardNeedsThePathToReachItsPrefix(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts/*' => ['GET']]],
        ]);

        // shorter than the prefix the pattern names, so there is nothing to cover
        $this->assertFalse($acl->allows('GET', '/api', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/', ['viewer']));
    }

    /**
     * `{name}` is a named placeholder for one segment, so a rule that mirrors the
     * route it guards reaches the real request: '/posts/{post_id}/comments' hits
     * '/posts/8757/comments'. It matches one value, so it adds no depth.
     */
    public function testAPlaceholderMatchesOneSegment(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/posts/{post_id}/comments' => ['GET']]],
        ]);

        $this->assertTrue($acl->allows('GET', '/posts/8757/comments', ['viewer']));
        $this->assertTrue($acl->allows('GET', '/posts/ALL/comments', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/posts/8757', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/posts/8757/comments/12', ['viewer']));
    }

    /**
     * A placeholder in the last position stays one segment, because it names a
     * value. That is where it parts ways with a trailing wildcard, which is the
     * subtree form: '/posts/{post_id}' is one post, '/posts/*' is the collection.
     */
    public function testATrailingPlaceholderIsNotASubtree(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/posts/{post_id}' => ['GET']]],
        ]);

        $this->assertTrue($acl->allows('GET', '/posts/8757', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/posts/8757/comments', ['viewer']));
    }

    public function testTheMethodIsCaseInsensitive(): void
    {
        $acl = $this->acl();

        $this->assertTrue($acl->allows('get', '/api/posts', ['viewer']));
        $this->assertTrue($acl->allows('Get', '/api/posts', ['viewer']));
    }

    public function testPatternsCoveringTheSamePathAreUnioned(): void
    {
        // A trailing '*' adds reach rather than precision, so on '/api/posts'
        // these two are level and their methods union: neither replaces the other.
        $acl = AclFeature::fromArray([
            'roles' => [
                'editor' => [
                    '/api/posts' => ['GET'],
                    '/api/posts/*' => ['POST'],
                ],
            ],
        ]);

        $this->assertTrue($acl->allows('GET', '/api/posts', ['editor']));
        $this->assertTrue($acl->allows('POST', '/api/posts', ['editor']));
    }

    /**
     * Specificity decides which matching rule applies: a literal segment beats a
     * placeholder, which beats the wildcard. A broad rule therefore no longer
     * widens a precise one sitting beside it.
     */
    public function testTheMostSpecificMatchingPatternDecides(): void
    {
        // the broad rule is listed first on purpose: the precise one wins anyway,
        // so the order of keys in the file decides nothing
        $acl = AclFeature::fromArray([
            'roles' => ['editor' => [
                '/posts/*/comments' => ['GET'],
                '/posts/ALL/comments' => ['POST'],
            ]],
        ]);

        // on its own path the literal rule wins, so only its methods apply
        $this->assertTrue($acl->allows('POST', '/posts/ALL/comments', ['editor']));
        $this->assertFalse($acl->allows('GET', '/posts/ALL/comments', ['editor']));
        // and the wildcard rule still governs every other value
        $this->assertTrue($acl->allows('GET', '/posts/42/comments', ['editor']));
        $this->assertFalse($acl->allows('POST', '/posts/42/comments', ['editor']));
    }

    public function testAPlaceholderBeatsTheWildcardAtTheSamePosition(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['editor' => [
                '/a/{name}/b' => ['GET'],
                '/a/*/b' => ['DELETE'],
            ]],
        ]);

        $this->assertTrue($acl->allows('GET', '/a/x/b', ['editor']));
        $this->assertFalse($acl->allows('DELETE', '/a/x/b', ['editor']));
    }

    /**
     * Equally specific patterns union, so two rules of the same precision both
     * count and the order of keys in the file never decides anything.
     */
    public function testEquallySpecificPatternsAreUnioned(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['editor' => [
                '/a/{x}/b' => ['GET'],
                '/a/{y}/b' => ['DELETE'],
            ]],
        ]);

        $this->assertTrue($acl->allows('GET', '/a/z/b', ['editor']));
        $this->assertTrue($acl->allows('DELETE', '/a/z/b', ['editor']));
    }

    // --- roles and users --------------------------------------------------

    public function testRolesAreUnioned(): void
    {
        $acl = $this->acl();

        // 'viewer' cannot POST, 'editor' can — the union grants it
        $this->assertFalse($acl->allows('POST', '/api/posts', ['viewer']));
        $this->assertTrue($acl->allows('POST', '/api/posts', ['viewer', 'editor']));
    }

    public function testRolesMayBeAStringOrAList(): void
    {
        $acl = $this->acl();

        $this->assertTrue($acl->allows('GET', '/api/posts', 'viewer'));
        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
        $this->assertTrue($acl->allows('GET', '/api/posts', ['ghost', 'viewer']));
    }

    public function testAnUnknownRoleIsDenied(): void
    {
        $this->assertFalse($this->acl()->allows('GET', '/api/posts', ['ghost']));
    }

    public function testANonScalarRoleIsDeniedRatherThanRaising(): void
    {
        // roleList() renders a non-scalar role as its type name, so it simply
        // stops matching — the same posture as an unknown role.
        $this->assertFalse($this->acl()->allows('GET', '/api/posts', [['viewer']]));
    }

    public function testAUserGrantAddsToTheRoleResult(): void
    {
        $acl = $this->acl();

        $this->assertFalse($acl->allows('GET', '/api/billing/9', ['viewer']));
        $this->assertTrue($acl->allows('GET', '/api/billing/9', ['viewer'], 42));
    }

    public function testAUserDenyOverridesTheRoleResult(): void
    {
        $acl = $this->acl();

        // 'editor' grants POST, but this user is denied on that exact path
        $this->assertTrue($acl->allows('POST', '/api/posts', ['editor']));
        $this->assertFalse($acl->allows('POST', '/api/posts', ['editor'], 42));
    }

    public function testAUserDenyBeatsAUserGrant(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts' => ['GET']]],
            'users' => [
                7 => [
                    'grant' => ['/api/posts/*' => ['DELETE']],
                    'deny' => ['/api/posts/*' => ['DELETE']],
                ],
            ],
        ]);

        $this->assertFalse($acl->allows('DELETE', '/api/posts/1', ['viewer'], 7));
    }

    public function testAnUnknownUserFallsBackToTheRoleResult(): void
    {
        $acl = $this->acl();

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer'], 999));
    }

    public function testAStringUserIdIsSupported(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts' => ['GET']]],
            'users' => ['alice' => ['grant' => ['/api/billing/*' => ['GET']]]],
        ]);

        $this->assertTrue($acl->allows('GET', '/api/billing/9', ['viewer'], 'alice'));
        $this->assertFalse($acl->allows('GET', '/api/billing/9', ['viewer'], 'bob'));
    }

    // --- the default outcome ---------------------------------------------

    public function testTheDefaultOutcomeAppliesWhenNoRoleMatches(): void
    {
        $acl = AclFeature::fromArray([
            'default' => true,
            'roles' => ['nobody' => ['/x' => ['GET']]],
        ]);

        $this->assertTrue($acl->allows('DELETE', '/anything', ['viewer']));
    }

    public function testItDeniesByDefaultWhenTheDefaultKeyIsOmitted(): void
    {
        $acl = AclFeature::fromArray([
            'roles' => ['viewer' => ['/api/posts' => ['GET']]],
        ]);

        $this->assertFalse($acl->allows('DELETE', '/anything', ['viewer']));
    }

    public function testAUserDenyOverridesADefaultOfTrue(): void
    {
        $acl = AclFeature::fromArray([
            'default' => true,
            'roles' => ['nobody' => ['/x' => ['GET']]],
            'users' => [7 => ['deny' => ['/anything' => ['DELETE']]]],
        ]);

        $this->assertTrue($acl->allows('DELETE', '/anything', ['viewer']));
        $this->assertFalse($acl->allows('DELETE', '/anything', ['viewer'], 7));
    }

    // --- the public surface ----------------------------------------------

    public function testForRequestMatchesAllows(): void
    {
        $acl = $this->acl();

        $this->assertSame(
            $acl->allows('POST', '/api/posts', ['editor'], 42),
            $acl->forRequest('POST', '/api/posts', ['editor'], 42)
        );
        $this->assertFalse($acl->forRequest('POST', '/api/posts', ['editor'], 42));
    }

    public function testDeniesIsTheNegationOfAllows(): void
    {
        $acl = $this->acl();

        $this->assertFalse($acl->denies('GET', '/api/posts', ['viewer']));
        $this->assertTrue($acl->denies('DELETE', '/api/posts', ['viewer']));
    }

    public function testAssertThrowsWhenDenied(): void
    {
        $this->expectException(DeniedException::class);
        $this->expectExceptionMessage('POST /api/posts denied for roles [viewer]');

        $this->acl()->assert('POST', '/api/posts', ['viewer']);
    }

    public function testAssertSaysNothingWhenAllowed(): void
    {
        $this->expectNotToPerformAssertions();

        $this->acl()->assert('GET', '/api/posts', ['viewer']);
    }

    public function testAssertNamesEveryRoleWhenSeveralAreGiven(): void
    {
        $this->expectException(DeniedException::class);
        $this->expectExceptionMessage('POST /api/posts denied for roles [viewer, ghost]');

        $this->acl()->assert('POST', '/api/posts', ['viewer', 'ghost']);
    }

    public function testWithUserBindsTheSubjectAndLeavesTheOriginalAlone(): void
    {
        $acl = $this->acl();
        $bound = $acl->withUser(42);

        $this->assertNotSame($acl, $bound);
        $this->assertTrue($bound->allows('GET', '/api/billing/9', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/billing/9', ['viewer']));
    }

    public function testAnExplicitUserIdOverridesTheBoundSubject(): void
    {
        $bound = $this->acl()->withUser(42);

        // 42 is granted /api/billing/*, but an explicit 999 takes precedence;
        // it has no rules, so the role result stands and the request is denied.
        $this->assertTrue($bound->allows('GET', '/api/billing/9', ['viewer']));
        $this->assertFalse($bound->allows('GET', '/api/billing/9', ['viewer'], 999));
    }

    public function testInstancesDoNotShareState(): void
    {
        $permissive = AclFeature::fromArray([
            'default' => true,
            'roles' => ['nobody' => ['/x' => ['GET']]],
        ]);
        $strict = AclFeature::fromArray([
            'roles' => ['nobody' => ['/x' => ['GET']]],
        ]);

        $this->assertTrue($permissive->allows('DELETE', '/anything', ['viewer']));
        $this->assertFalse($strict->allows('DELETE', '/anything', ['viewer']));
    }

    public function testTheDeniedExceptionIsReachableAsBothOfItsParents(): void
    {
        $denied = new DeniedException('x');

        $this->assertInstanceOf(AclFeatureException::class, $denied);
        $this->assertInstanceOf(RuntimeException::class, $denied);
    }

    // --- loading from a file ---------------------------------------------

    public function testFromFileLoadsAValidConfig(): void
    {
        $acl = AclFeature::fromFile($this->config . '/valid.php');

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
        $this->assertFalse($acl->allows('DELETE', '/api/posts', ['viewer']));
        // user 42 denies POST on that path
        $this->assertFalse($acl->allows('POST', '/api/posts', ['editor'], 42));
    }

    public function testFromFileThrowsWhenTheFileIsMissing(): void
    {
        $this->expectException(AclFeatureException::class);
        $this->expectExceptionMessage('not found or not readable');

        AclFeature::fromFile($this->config . '/missing.php');
    }

    public function testFromFileThrowsWhenTheFileIsNotReadable(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'acl-feature-');
        self::assertIsString($file);
        file_put_contents($file, "<?php return ['roles' => ['viewer' => ['/x' => ['GET']]]];");
        chmod($file, 0000);

        try {
            if (is_readable($file)) {
                self::markTestSkipped('file permissions are ignored here (running as root?)');
            }

            $this->expectException(AclFeatureException::class);
            $this->expectExceptionMessage('not found or not readable');

            AclFeature::fromFile($file);
        } finally {
            chmod($file, 0644);
            unlink($file);
        }
    }

    public function testFromFileThrowsWhenTheConfigIsNotAnArray(): void
    {
        $this->expectException(AclFeatureException::class);
        $this->expectExceptionMessage('must return an array, got string');

        AclFeature::fromFile($this->config . '/not-array.php');
    }

    public function testFromFileNamesTheFileWhenAnEntryIsBad(): void
    {
        $file = $this->config . '/bad-entry.php';

        $this->expectException(AclFeatureException::class);
        $this->expectExceptionMessage("Invalid path pattern 'api/posts' for role 'editor': {$file}");

        AclFeature::fromFile($file);
    }
}
