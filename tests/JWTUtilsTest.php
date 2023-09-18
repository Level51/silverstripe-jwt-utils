<?php

namespace Level51\JWTUtils\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Security\BasicAuth;
use Level51\JWTUtils\JWTUtils;
use Level51\JWTUtils\JWTUtilsException;

class JWTUtilsTest extends SapphireTest
{

    protected static $fixture_file = 'JWTUtilsTest.yml';

    public function setUp(): void
    {
        parent::setUp();

        $config = Config::inst();

        $config->set(JWTUtils::class, 'secret', 'my-super-secret');
        $config->set(BasicAuth::class, 'ignore_cli', false);
    }

    public function tearDown(): void
    {
        parent::tearDown();

        JWTUtils::tearDown();
    }

    public function testSingleton(): void
    {
        $inst = JWTUtils::inst();

        $this->assertEquals(get_class($inst), JWTUtils::class);
    }

    public function testMissingSecret(): void
    {
        $this->expectException(JWTUtilsException::class);

        Config::inst()->set(JWTUtils::class, 'secret', null);
        JWTUtils::inst();
    }

    public function testGetClaims(): void
    {
        $claims = JWTUtils::inst()->getClaims();

        $this->assertTrue(is_array($claims));
    }

    public function testCustomIssClaim(): void
    {
        $iss = 'my-app-backend';

        Config::inst()->set(JWTUtils::class, 'iss', $iss);

        $claims = JWTUtils::inst()->getClaims();

        $this->assertEquals($claims['iss'], $iss);
    }

    private function loginByBasicAuth(bool $includeMemberData = true, bool $incorrectPassword = false): mixed
    {
        $request = new HTTPRequest('GET', '');
        $request->addHeader('PHP_AUTH_USER', 'test@test.test');
        $request->addHeader('PHP_AUTH_PW', $incorrectPassword ? 'my-wrong-password' : 'my-test-password');

        return JWTUtils::inst()->byBasicAuth($request, $includeMemberData);
    }

    public function testBasicAuthFail(): void
    {
        $this->expectException(JWTUtilsException::class);

        $this->loginByBasicAuth(false, true);
    }

    public function testBasicAuthSuccess(): void
    {
        // Generate JWT from member stub
        $payload = $this->loginByBasicAuth(false);

        $this->assertTrue(is_array($payload));
        $this->assertTrue(array_key_exists('token', $payload));
    }

    public function testBasicAuthWithMemberSuccess()
    {
        $payload = $this->loginByBasicAuth();

        $this->assertTrue(is_array($payload));
        $this->assertEquals(count($payload), 2);
        $this->assertEquals(array_keys($payload)[1], 'member');
        $this->assertEquals($payload['member']['email'], 'test@test.test');
    }

    public function testValidToken(): void
    {
        // Generate JWT with member data from stub
        $payload = $this->loginByBasicAuth(false);

        $this->assertTrue(JWTUtils::inst()->check($payload['token']));
    }

    public function testInvalidTokenSecret(): void
    {
        // Generate JWT with member data from stub
        $payload = $this->loginByBasicAuth(false);

        // Change secret
        Config::inst()->set(JWTUtils::class, 'secret', 'other-secret');

        $this->assertFalse(JWTUtils::inst()->check($payload['token']));
    }

    public function testDoNotRenew(): void
    {
        // Generate JWT with member data from stub
        $payload = $this->loginByBasicAuth(false);

        $firstToken = $payload['token'];

        // Renew attempt: Deliver same token
        $renewedToken = JWTUtils::inst()->renew($firstToken);

        $this->assertEquals($firstToken, $renewedToken);
    }

    public function testRenew(): void
    {
        // Generate JWT with member data from stub
        $payload = $this->loginByBasicAuth(false);

        $firstToken = $payload['token'];

        // Renew attempt: Deliver new token
        Config::inst()->set(JWTUtils::class, 'renew_threshold_in_minutes', 0);

        sleep(1);

        $renewedToken = JWTUtils::inst()->renew($firstToken);

        $this->assertNotEquals($firstToken, $renewedToken);
    }

}
