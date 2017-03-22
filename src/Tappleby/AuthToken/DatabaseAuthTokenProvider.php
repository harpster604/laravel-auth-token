<?php
/*
 * User: tappleby
 * Date: 2013-05-11
 * Time: 4:07 PM
 */

namespace Tappleby\AuthToken;

use \Illuminate\Contracts\Auth\Authenticatable;
use \Illuminate\Database\Connection;
use \Illuminate\Encryption\McryptEncrypter;

class DatabaseAuthTokenProvider extends AbstractAuthTokenProvider {

  /**
   * @var \Illuminate\Database\Connection
   */
  protected $conn;

  protected $table;

  /**
   * @param Connection $conn
   * @param string $table
   * @param \Illuminate\Encryption\Encrypter $encrypter
   * @param \Tappleby\AuthToken\HashProvider $hasher
   */
  function __construct(Connection $conn, $table, McryptEncrypter $encrypter, HashProvider $hasher)
  {
    parent::__construct($encrypter, $hasher);
    $this->table = $table;
    $this->conn = $conn;
  }

  /**
   * @return \Illuminate\Database\Connection
   */
  public function getConnection()
  {
    return $this->conn;
  }

  /**
   * @return \Illuminate\Database\Query\Builder
   */
  protected function db() {
    return $this->conn->table($this->table);
  }

  /**
   * Creates an auth token for user.
   *
   * @param \Illuminate\Contracts\Auth\Authenticatable $user
   * @return \TAppleby\AuthToken\AuthToken|false
   */
  public function create(Authenticatable $user)
  {
    if($user == null || $user->getAuthIdentifier() == null) {
      return false;
    }

    $token = $this->generateAuthToken();
    $token->setAuthIdentifier( $user->getAuthIdentifier() );

    $t = new \DateTime;
    $insertData = array_merge($token->toArray(), array(
       'created_at' => $t, 'updated_at' => $t
    ));

    $this->db()->insert($insertData);

    return $token;
  }

  /**
   * Find user id from auth token.
   *
   * @param $serializedAuthToken string
   * @return \TAppleby\AuthToken\AuthToken|null
   */
  public function find($serializedAuthToken)
  {
    $authToken = $this->deserializeToken($serializedAuthToken);

    if($authToken == null) {
      return null;
    }

    if(!$this->verifyAuthToken($authToken)) {
      return null;
    }

    $res = $this->db()
                ->where('auth_identifier', $authToken->getAuthIdentifier())
                ->where('public_key', $authToken->getPublicKey())
                ->where('private_key', $authToken->getPrivateKey())
                ->first();

    if($res == null) {
      return null;
    }

    return $authToken;
  }


    /**
     * @param UserInterface|mixed $serializedAuthToken
     * @return bool
     */
    public function purge($serializedAuthToken)
    {
        $authToken = $this->deserializeToken($serializedAuthToken);
        if($authToken == null) {
            return false;
        }
        if(!$this->verifyAuthToken($authToken)) {
            return false;
        }
        $res = $this->db()
            ->where('auth_identifier', $authToken->getAuthIdentifier())
            ->where('public_key', $authToken->getPublicKey())
            ->where('private_key', $authToken->getPrivateKey())
            ->delete();
        return $res > 0;
    }

  /**
   * @param mixed|\Illuminate\Contracts\Auth\Authenticatable $identifier
   * @return bool
   */
  /*
  public function purge($identifier)
  {
    if($identifier instanceof Authenticatable) {
      $identifier = $identifier->getAuthIdentifier();
    }

    $res = $this->db()->where('auth_identifier', $identifier)->delete();

    return $res > 0;
  }*/
}