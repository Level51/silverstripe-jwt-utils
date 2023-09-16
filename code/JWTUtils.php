<?php

namespace Level51\JWTUtils;

use Level51\JWTUtils\JWTUtilsException;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Security\BasicAuth;
use SilverStripe\Control\HTTPResponse_Exception;
use \Firebase\JWT\JWT as JWT;
use \Carbon\Carbon;
use \Ramsey\Uuid\Uuid;

/**
 * Utility Class for handling JWTs.
 */
class JWTUtils {

    /**
     * @var int Config: JWT lifetime
     */
    private static $lifetime_in_days = 7;

    /**
     * @var int Config: Relevant for 'rat' claim (renewed at)
     */
    private static $renew_threshold_in_minutes = 60;

    /**
     * @var JWTUtils Singleton instance holder
     */
    private static $instance = null;

    /**
     * @return JWTUtils
     * @throws JWTUtilsException
     */
    public static function inst() {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Clears the singleton instance. Helps with PHPUnit testing.
     */
    public static function tearDown() {
        self::$instance = null;
    }

    /**
     * JWTUtils constructor.
     * @throws JWTUtilsException
     */
    private function __construct() {
        if (!$this->hasValidSecret()) {
            throw new JWTUtilsException('No "secret" config found.');
        }
    }

    /**
     * Disables the magic clone method
     */
    private function __clone() { }

    /**
     * Checks for a valid "secret" config
     *
     * @return bool
     */
    private function hasValidSecret() {
        return boolval(Injector::inst()->convertServiceProperty(Config::inst()->get(self::class, 'secret')));
    }

    /**
     * @return int Unix timestamp of token expiration
     */
    private function calcExpirationClaim() {
        return Carbon::now()->addDays(Config::inst()->get(self::class, 'lifetime_in_days'))->timestamp;
    }

    /**
     * Generates a fresh set of default claims.
     *
     * @return array
     */
    public function getClaims() {
        return [
            'iss' => Config::inst()->get(self::class, 'iss') ?: Director::absoluteBaseURL(),
            'exp' => $this->calcExpirationClaim(),
            'iat' => time(),
            'rat' => time(),
            'jti' => Uuid::uuid4()->toString()
        ];
    }

    /**
     * Creates a new token from Basic Auth member data
     *
     * @param bool $includeMemberData
     *
     * @return array
     * @throws JWTUtilsException
     */
    public function byBasicAuth($request, $includeMemberData = true) {

        // Try to authenticate member with basic auth
        try {
            $member = BasicAuth::requireLogin($request, null, false);
        } catch (HTTPResponse_Exception $e) {
            throw new JWTUtilsException($e->getResponse()->getBody());
        }

        // Create JWT with all claims
        $token = JWT::encode(
            array_merge([
                'memberId' => $member->ID
            ], $this->getClaims()),
            Config::inst()->get(self::class, 'secret'));

        $payload = [
            'token' => $token
        ];

        // Check if member data should be included
        if ($includeMemberData) {
            $payload['member'] = [
                'id'        => $member->ID,
                'email'     => $member->Email,
                'firstName' => $member->FirstName,
                'surname'   => $member->Surname
            ];
        }

        return $payload;
    }

    /**
     * Checks if the given token is valid and needs to be renewed
     *
     * @param string $token The decoded token to renew
     *
     * @return string The renewed decoded token
     * @throws JWTUtilsException            Provided JWT was: simply invalid, invalid because the signature verification failed, since expired, as defined by the 'exp' claim
     */
    public function renew($token) {

        try {
            $jwt = (array)JWT::decode(
                $token,
                Config::inst()->get(self::class, 'secret'),
                ['HS256']);
        } catch (\Exception $e) {
            throw new JWTUtilsException($e->getMessage());
        }

        // TODO: Check if script reaches this point if exp claim is in past

        // Check if token needs to be renewed
        $renewedAt = Carbon::createFromTimestamp($jwt['rat']);
        if ($renewedAt->diffInMinutes(Carbon::now()) <
            Config::inst()->get(self::class, 'renew_threshold_in_minutes')) {

            // Token was refreshed less than an hour ago, return same token
            return $token;
        }

        // Update 'exp' and 'rat' claims
        $jwt['exp'] = $this->calcExpirationClaim();
        $jwt['rat'] = time();

        // Renew and return token
        return JWT::encode(
            $jwt,
            Config::inst()->get(self::class, 'secret'));
    }

    /**
     * Checks if token is valid and non-expired
     *
     * @param string $token
     *
     * @return bool
     */
    public function check($token) {
        try {
            JWT::decode(
                $token,
                Config::inst()->get(self::class, 'secret'),
                ['HS256']);

            return true;
        } catch (\Exception $e) {

            return false;
        }
    }
}
