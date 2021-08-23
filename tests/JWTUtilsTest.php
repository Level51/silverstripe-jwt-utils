<?php

namespace Level51\JWTUtils\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Convert;
use SilverStripe\Dev\TestOnly;
use Level51\JWTUtils\JWTUtils;
use Level51\JWTUtils\JWTUtilsException;

class JWTUtilsTest extends SapphireTest {

    protected static $fixture_file = 'JWTUtilsTest.yml';

    private $config;
    private $origUser;
    private $origPw;

    public function setUp() {
        parent::setUp();

        Config::inst()->update(JWTUtils::class, 'secret', 'my-super-secret');
        $this->config = [
            'lifetimeInDays' => Config::inst()->get(JWTUtils::class, 'lifetime_in_days'),
            'renewThreshold' => Config::inst()->get(JWTUtils::class, 'renew_threshold_in_minutes'),
            'secret'         => Config::inst()->get(JWTUtils::class, 'secret')
        ];

        $this->origUser = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : null;
        $this->origPw = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : null;
    }

    public function tearDown() {
        parent::tearDown();

        JWTUtils::tearDown();
        $_SERVER['PHP_AUTH_USER'] = $this->origUser;
        $_SERVER['PHP_AUTH_PW'] = $this->origPw;
    }

    public function testSingleton() {
        $inst = JWTUtils::inst();

        $this->assertEquals(get_class($inst), JWTUtils::class);
    }

    public function testMissingSecret() {
        $this->setExpectedException(JWTUtilsException::class);

        Config::inst()->update(JWTUtils::class, 'secret', null);
        JWTUtils::inst();
    }

    public function testGetClaims() {
        $claims = JWTUtils::inst()->getClaims();

        $this->assertTrue(is_array($claims));
    }

    public function testCustomIssClaim() {
        $iss = 'my-app-backend';
        Config::inst()->update(JWTUtils::class, 'iss', $iss);
        $claims = JWTUtils::inst()->getClaims();

        $this->assertEquals($claims['iss'], $iss);
    }

    public function testBasicAuthFail() {
        $this->setExpectedException(JWTUtilsException::class);

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-failed-password';

        JWTUtils::inst()->byBasicAuth();
    }

    public function testBasicAuthSuccess() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT from member stub
        $payload = JWTUtils::inst()->byBasicAuth(false);

        $this->assertTrue(is_array($payload));
        $this->assertTrue(array_key_exists('token', $payload));
    }

    public function testBasicAuthWithMemberSuccess() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT with member data from stub
        $payload = JWTUtils::inst()->byBasicAuth();

        $this->assertTrue(is_array($payload));
        $this->assertEquals(count($payload), 2);
        $this->assertEquals(array_keys($payload)[1], 'member');
        $this->assertEquals($payload['member']['email'], 'test@test.test');
    }

    public function testValidToken() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT with member data from stub
        $payload = JWTUtils::inst()->byBasicAuth();

        $this->assertTrue(JWTUtils::inst()->check($payload['token']));
    }

    public function testInvalidTokenSecret() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT with member data from stub
        $payload = JWTUtils::inst()->byBasicAuth();

        // Change secret
        Config::inst()->update(JWTUtils::class, 'secret', 'other-secret');

        $this->assertFalse(JWTUtils::inst()->check($payload['token']));
    }

    public function testDoNotRenew() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT with member data from stub
        $payload = JWTUtils::inst()->byBasicAuth();
        $firstToken = $payload['token'];

        // Renew attempt: Deliver same token
        $renewedToken = JWTUtils::inst()->renew($firstToken);

        $this->assertEquals($firstToken, $renewedToken);
    }

    public function testRenew() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        // Generate JWT with member data from stub
        $payload = JWTUtils::inst()->byBasicAuth();
        $firstToken = $payload['token'];

        // Renew attempt: Deliver new token
        Config::inst()->update(JWTUtils::class, 'renew_threshold_in_minutes', 0);
        sleep(1);
        $renewedToken = JWTUtils::inst()->renew($firstToken);

        $this->assertNotEquals($firstToken, $renewedToken);
    }

    public function testFailedTokenRequestDueToCredentials() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-wrong-test-password';

        $response = Director::test('JWTUtils_TestController');
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function testFailedTokenRequestDueToMissingSecret() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        Config::inst()->update(JWTUtils::class, 'secret', null);
        $response = Director::test('JWTUtils_TestController');
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function testSuccessfulTokenRequest() {

        // Mock credentials
        $_SERVER['PHP_AUTH_USER'] = 'test@test.test';
        $_SERVER['PHP_AUTH_PW'] = 'my-test-password';

        $response = Director::test('JWTUtils_TestController');
        $payload = Convert::json2array($response->getBody());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue(array_key_exists('token', $payload));
    }
}

class JWTUtils_TestController extends Controller implements TestOnly {

    public function index() {
        try {
            $payload = JWTUtils::inst()->byBasicAuth();

            return Convert::array2json($payload);
        } catch (JWTUtilsException $e) {
            return $this->httpError(403, $e->getMessage());
        }
    }
}
