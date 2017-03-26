<?php
/*
 * User: tappleby
 * Date: 2013-05-11
 * Time: 7:34 PM
 */

namespace Tappleby\AuthToken;


class HashProvider {
  private $algo = 'sha256';
  private $hashKey;

  public function getAlgo()
  {
    return $this->algo;
  }

  public function getHashKey()
  {
    return $this->hashKey;
  }

  function __construct($hashKey)
  {
    $this->hashKey = $hashKey;
  }

  public function make($entropy=null)
  {
    if(empty($entropy)) {
      $entropy = $this->generateEntropy();
    }

    return hash($this->algo, $entropy);
  }

  public function makePrivate($publicKey)
  {
    return hash_hmac($this->algo, $publicKey, $this->hashKey);
  }

  public function check($publicKey, $privateKey) {
    $genPublic = $this->makePrivate($publicKey);
    return $genPublic == $privateKey;
  }

  public function generateEntropy() {
    $entropy = openssl_random_pseudo_bytes(32);
    $entropy .= uniqid(mt_rand(), true);

    return $entropy;
  }
}