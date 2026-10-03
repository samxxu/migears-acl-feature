<?php

declare(strict_types=1);

namespace MiGears\AclFeature\Tests;

use MiGears\AclFeature\AclFeature;
use PHPUnit\Framework\TestCase;

/**
 * The README is the module's front door, and a documented example that no
 * longer holds is worse than no example. These tests pin the two things a
 * reader copies: the worked outcomes under "Evaluation order", and the version
 * badge, which has to agree with composer.json and the class constant.
 */
final class ReadmeConsistencyTest extends TestCase
{
    private const README = __DIR__ . '/../README.md';

    private static function readme(): string
    {
        $readme = file_get_contents(self::README);
        self::assertIsString($readme);

        return $readme;
    }

    private static function composerVersion(): string
    {
        $composer = json_decode((string) file_get_contents(__DIR__ . '/../composer.json'), true);
        self::assertIsArray($composer);

        $version = $composer['version'] ?? null;
        self::assertIsString($version);

        return $version;
    }

    /**
     * The config from the README's Quick Start, transcribed as the test's own
     * copy: if the README block changes shape, this copy has to be reconciled
     * with it rather than silently drifting.
     */
    private function configuredAcl(): AclFeature
    {
        return AclFeature::fromArray([
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
        ]);
    }

    public function testTheWorkedExampleInTheReadmeHolds(): void
    {
        $acl = $this->configuredAcl();

        $this->assertTrue($acl->allows('GET', '/api/posts', ['viewer']));
        $this->assertFalse($acl->allows('POST', '/api/posts', ['viewer']));
        $this->assertTrue($acl->allows('POST', '/api/posts', ['viewer', 'editor']));
        $this->assertTrue($acl->allows('GET', '/api/posts/42/comments', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/postscript', ['viewer']));
        $this->assertFalse($acl->allows('GET', '/api/billing/9', ['viewer']));
        $this->assertTrue($acl->allows('GET', '/api/billing/9', ['viewer'], 42));
        $this->assertFalse($acl->allows('POST', '/api/posts', ['editor'], 42));
    }

    /**
     * The three places the version lives: the composer.json field, the class
     * constant, and the two README badges — one per language half.
     */
    public function testTheVersionAgreesInEveryPlaceItIsDeclared(): void
    {
        $version = self::composerVersion();

        $this->assertSame($version, AclFeature::VERSION);
        $this->assertSame(
            2,
            substr_count(self::readme(), "version-{$version}-blue"),
            'the English half and the Chinese half each carry the version badge'
        );
    }

    public function testTheReadmeNamesTheConfigFileItTellsTheReaderToWrite(): void
    {
        $this->assertStringContainsString('config/acl-feature.php', self::readme());
    }
}
