<?php
/**
 * =====================================================================================
 * Class for base module for Kakaocert API SDK. It include base functionality for
 * RESTful web service request and parse json result. It uses Linkhub module
 * to accomplish authentication APIs.
 *
 * This module uses curl and openssl for HTTPS Request. So related modules must
 * be installed and enabled.
 *
 * http://www.linkhub.co.kr
 * Author : Jeogn Yohan (code@linkhub.co.kr)
 * Written : 2020-04-23
 * Updated : 2020-09-08
 *
 * Thanks for your interest.
 * We welcome any suggestions, feedbacks, blames or anythings.
 * ======================================================================================
 */

require_once 'Linkhub/linkhub.auth.php';

class KakaocertService
{
  const ServiceID = 'KAKAOCERT';
  const ServiceURL = 'https://kakaocert-api.linkhub.co.kr';
  const Version = '1.0';

  private $Token_Table = array();
  private $Linkhub;
  private $IsTest = false;
  private $IPRestrictOnOff = true;
  private $scopes = array();
  private $__requestMode = LINKHUB_COMM_MODE;

  public function __construct($LinkID, $SecretKey)
  {
    $this->Linkhub = Linkhub::getInstance($LinkID, $SecretKey);
    $this->scopes[] = 'member';
    $this->scopes[] = '310';
    $this->scopes[] = '320';
    $this->scopes[] = '330';
  }

  protected function AddScope($scope)
  {
    $this->scopes[] = $scope;
  }

  public function IPRestrictOnOff($V)
  {
      $this->IPRestrictOnOff = $V;
  }


  private function getsession_Token($CorpNum)
  {
    $targetToken = null;

    if (array_key_exists($CorpNum, $this->Token_Table)) {
      $targetToken = $this->Token_Table[$CorpNum];
    }

    $Refresh = false;

    if (is_null($targetToken)) {
      $Refresh = true;
    } else {
      $Expiration = new DateTime($targetToken->expiration, new DateTimeZone("UTC"));

      $now = $this->Linkhub->getTime();
      $Refresh = $Expiration < $now;
    }

    if ($Refresh) {
      try {
        $targetToken = $this->Linkhub->getToken(KakaocertService::ServiceID, $CorpNum, $this->scopes, $this->IPRestrictOnOff ? null : "*");
      } catch (LinkhubException $le) {
        throw new KakaocertException($le->getMessage(), $le->getCode());
      }
      $this->Token_Table[$CorpNum] = $targetToken;
    }
    return $targetToken->session_token;
  }
  protected function executeCURL($uri, $ClientCode = null, $userID = null, $isPost = false, $action = null, $postdata = null, $isMultiPart = false, $contentsType = null)
  {
    if ($this->__requestMode != "STREAM") {
      $http = curl_init(KakaocertService::ServiceURL . $uri);
      $header = array();

      if (is_null($ClientCode) == false) {
        $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      }

      $header[] = 'Content-Type: Application/json';

      if ($isPost) {
        curl_setopt($http, CURLOPT_POST, 1);
        curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);

        $xDate = $this->Linkhub->getTime();

        $digestTarget = 'POST'.chr(10);
        $digestTarget = $digestTarget.base64_encode(md5($postdata,true)).chr(10);
        $digestTarget = $digestTarget.$xDate.chr(10);

        $digestTarget = $digestTarget.Linkhub::VERSION.chr(10);

        $digest = base64_encode(hash_hmac('sha1',$digestTarget,base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')),true));

        $header[] = 'x-lh-date: '.$xDate;
        $header[] = 'x-lh-version: '.Linkhub::VERSION;
        $header[] = 'x-kc-auth: '.$this->Linkhub->getLinkID().' '.$digest;

      }

      curl_setopt($http, CURLOPT_HTTPHEADER, $header);
      curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($http, CURLOPT_ENCODING, 'gzip,deflate');

      $responseJson = curl_exec($http);
      $http_status = curl_getinfo($http, CURLINFO_HTTP_CODE);

      $is_gzip = 0 === mb_strpos($responseJson, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $responseJson = $this->Linkhub->gzdecode($responseJson);
      }

      $contentType = strtolower(curl_getinfo($http, CURLINFO_CONTENT_TYPE));

      curl_close($http);
      if ($http_status != 200) {
        throw new KakaocertException($responseJson);
      }

      if( 0 === mb_strpos($contentType, 'application/pdf')) {
        return $responseJson;
      }
      return json_decode($responseJson);

    } else {
      $header = array();

      $header[] = 'Accept-Encoding: gzip,deflate';
      $header[] = 'Connection: close';
      if (is_null($ClientCode) == false) {
        $header[] = 'Authorization: Bearer ' . $this->getsession_Token($ClientCode);
      }

      if ($isMultiPart == false) {
        $header[] = 'Content-Type: Application/json';
        $postbody = $postdata;


        $xDate = $this->Linkhub->getTime();

        $digestTarget = 'POST'.chr(10);
        $digestTarget = $digestTarget.base64_encode(md5($postdata,true)).chr(10);
        $digestTarget = $digestTarget.$xDate.chr(10);

        $digestTarget = $digestTarget.Linkhub::VERSION.chr(10);

        $digest = base64_encode(hash_hmac('sha1',$digestTarget,base64_decode(strtr($this->Linkhub->getSecretKey(), '-_', '+/')),true));

        $header[] = 'x-lh-date: '.$xDate;
        $header[] = 'x-lh-version: '.Linkhub::VERSION;
        $header[] = 'x-kc-auth: '.$this->Linkhub->getLinkID().' '.$digest;


      }

      $params = array(
        'http' => array(
        'ignore_errors' => TRUE,
        'protocol_version' => '1.0',
        'method' => 'GET'
      ));

      if ($isPost) {
        $params['http']['method'] = 'POST';
        $params['http']['content'] = $postbody;
      }

      if ($header !== null) {
        $head = "";
        foreach ($header as $h) {
          $head = $head . $h . "\r\n";
        }
        $params['http']['header'] = substr($head, 0, -2);
      }

      $ctx = stream_context_create($params);
      $response = file_get_contents(KakaocertService::ServiceURL . $uri, false, $ctx);

      $is_gzip = 0 === mb_strpos($response, "\x1f" . "\x8b" . "\x08");

      if ($is_gzip) {
        $response = $this->Linkhub->gzdecode($response);
      }

      if ($http_response_header[0] != "HTTP/1.1 200 OK") {
        throw new KakaocertException($response);
      }

      foreach( $http_response_header as $k=>$v )
      {
        $t = explode( ':', $v, 2 );
        if( preg_match('/^Content-Type:/i', $v, $out )) {
          $contentType = trim($t[1]);
          if( 0 === mb_strpos($contentType, 'application/pdf')) {
            return $response;
          }
        }
      }

      return json_decode($response);
    }
  }

  public function requestESign($ClientCode, $RequestESign, $appUseYN = false)
  {
    $RequestESign->isAppUseYN = $appUseYN;

    $postdata = json_encode($RequestESign);
    return $this->executeCURL('/SignToken/Request', $ClientCode, null, true, null, $postdata);
  }

  public function getESignState($ClientCode, $receiptID)
  {
    if (is_null($receiptID) || empty($receiptID)) {
      throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
    }

    $uri = '/SignToken/Status/' . $receiptID;

    $result = $this->executeCURL($uri, $ClientCode);

    $ResultESign = new ResultESign();
    $ResultESign->fromJsonInfo($result);
    return $ResultESign;
  }

  public function requestVerifyAuth($ClientCode, $RequestVerifyAuth)
  {
    $postdata = json_encode($RequestVerifyAuth);
    return $this->executeCURL('/SignIdentity/Request', $ClientCode, null, true, null, $postdata)->receiptId;
  }

  public function getVerifyAuthState($ClientCode, $receiptID)
  {
      if (is_null($receiptID) || empty($receiptID)) {
          throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
      }
      $result = $this->executeCURL('/SignIdentity/Status/' . $receiptID, $ClientCode);

      $ResultVerifyAuth = new ResultVerifyAuth();
      $ResultVerifyAuth->fromJsonInfo($result);
      return $ResultVerifyAuth;
  }

   public function requestCMS($ClientCode, $RequestCMS)
   {
     $postdata = json_encode($RequestCMS);
     return $this->executeCURL('/SignDirectDebit/Request', $ClientCode, null, true, null, $postdata)->receiptId;
   }

   public function getCMSState($ClientCode, $receiptID)
  {
      if (is_null($receiptID) || empty($receiptID)) {
          throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
      }
      $result = $this->executeCURL('/SignDirectDebit/Status/' . $receiptID, $ClientCode);

      $ResultCMS = new ResultCMS();
      $ResultCMS->fromJsonInfo($result);
      return $ResultCMS;
  }

  public function verifyESign($ClientCode, $receiptID, $signature = null)
  {
    if (is_null($receiptID) || empty($receiptID)) {
      throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
    }

    $uri = '/SignToken/Verify/' . $receiptID;

    if (!is_null($signature) || !empty($signature)) {
      $uri .= '/'.$signature;
    }

    return $this->executeCURL($uri, $ClientCode);
  }

  public function verifyAuth($ClientCode, $receiptID)
  {
    if (is_null($receiptID) || empty($receiptID)) {
      throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
    }

    return $this->executeCURL('/SignIdentity/Verify/' . $receiptID, $ClientCode);
  }

  public function verifyCMS($ClientCode, $receiptID)
  {
     if (is_null($receiptID) || empty($receiptID)) {
       throw new KakaocertException('접수아이디가 입력되지 않았습니다.');
     }
     return $this->executeCURL('/SignDirectDebit/Verify/' . $receiptID, $ClientCode);
  }
} // end of KakaocertService

class KakaocertException extends Exception
{
    public function __construct($response, $code = -99999999, Exception $previous = null)
    {
        $Err = json_decode($response);
        if (is_null($Err)) {
            parent::__construct($response, $code);
        } else {
            parent::__construct($Err->message, $Err->code);
        }
    }

    public function __toString()
    {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}

class RequestCMS
{
  public $CallCenterNum;
	public $Expires_in;
	public $PayLoad;
	public $ReceiverBirthDay;
	public $ReceiverHP;
	public $ReceiverName;
	public $SubClientID;
	public $TMSMessage;
	public $TMSTitle;

	public $isAllowSimpleRegistYN;
	public $isVerifyNameYN;

  public $BankAccountName;
	public $BankAccountNum;
	public $BankCode;
	public $ClientUserID;

}

class ResultCMS
{
  public $receiptID;
	public $regDT;
	public $state;

	public $expires_in;
	public $callCenterNum;

	public $allowSimpleRegistYN;
	public $verifyNameYN;
	public $payload;
	public $requestDT;
	public $expireDT;
	public $clientCode;
	public $clientName;
	public $tmstitle;
	public $tmsmessage;

	public $subClientName;
	public $subClientCode;
	public $viewDT;
	public $completeDT;
	public $verifyDT;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->regDT) ? $this->regDT = $jsonInfo->regDT : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;

    isset($jsonInfo->expires_in) ? $this->expires_in = $jsonInfo->expires_in : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;
    
    isset($jsonInfo->allowSimpleRegistYN) ? $this->allowSimpleRegistYN = $jsonInfo->allowSimpleRegistYN : null;
    isset($jsonInfo->verifyNameYN) ? $this->verifyNameYN = $jsonInfo->verifyNameYN : null;
    isset($jsonInfo->payload) ? $this->payload = $jsonInfo->payload : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->clientName) ? $this->clientName = $jsonInfo->clientName : null;
    isset($jsonInfo->tmstitle) ? $this->tmstitle = $jsonInfo->tmstitle : null;
    isset($jsonInfo->tmsmessage) ? $this->tmsmessage = $jsonInfo->tmsmessage : null;

    isset($jsonInfo->subClientName) ? $this->subClientName = $jsonInfo->subClientName : null;
    isset($jsonInfo->subClientCode) ? $this->subClientCode = $jsonInfo->subClientCode : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;

  }
}


class RequestVerifyAuth
{
  public $CallCenterNum;
	public $Expires_in;
	public $PayLoad;
	public $ReceiverBirthDay;
	public $ReceiverHP;
	public $ReceiverName;
	public $SubClientID;
	public $TMSMessage;
	public $TMSTitle;
	public $Token;
	public $isAllowSimpleRegistYN;
	public $isVerifyNameYN;
}

class ResultVerifyAuth
{
  public $receiptID;
	public $regDT;
	public $state;

	public $expires_in;
	public $callCenterNum;

	public $allowSimpleRegistYN;
	public $verifyNameYN;
	public $payload;
	public $requestDT;
	public $expireDT;
	public $clientCode;
	public $clientName;
	public $tmstitle;
	public $tmsmessage;

	public $subClientName;
	public $subClientCode;
	public $viewDT;
	public $completeDT;
	public $verifyDT;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->regDT) ? $this->regDT = $jsonInfo->regDT : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;

    isset($jsonInfo->expires_in) ? $this->expires_in = $jsonInfo->expires_in : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;

    isset($jsonInfo->allowSimpleRegistYN) ? $this->allowSimpleRegistYN = $jsonInfo->allowSimpleRegistYN : null;
    isset($jsonInfo->verifyNameYN) ? $this->verifyNameYN = $jsonInfo->verifyNameYN : null;
    isset($jsonInfo->payload) ? $this->payload = $jsonInfo->payload : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->clientName) ? $this->clientName = $jsonInfo->clientName : null;
    isset($jsonInfo->tmstitle) ? $this->tmstitle = $jsonInfo->tmstitle : null;
    isset($jsonInfo->tmsmessage) ? $this->tmsmessage = $jsonInfo->tmsmessage : null;

    isset($jsonInfo->subClientName) ? $this->subClientName = $jsonInfo->subClientName : null;
    isset($jsonInfo->subClientCode) ? $this->subClientCode = $jsonInfo->subClientCode : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
  }
}


class RequestESign
{
  public $CallCenterNum;
	public $Expires_in;
	public $PayLoad;
	public $ReceiverBirthDay;
	public $ReceiverHP;
	public $ReceiverName;
	public $SubClientID;
	public $TMSMessage;
	public $TMSTitle;
	public $Token;
	public $isAllowSimpleRegistYN;
	public $isVerifyNameYN;
  public $isAppUseYN;
}


class ResultESign
{
  public $receiptID;
	public $regDT;
	public $state;

	public $expires_in;
	public $callCenterNum;

	public $allowSimpleRegistYN;
	public $verifyNameYN;
	public $payload;
	public $requestDT;
	public $expireDT;
	public $clientCode;
	public $clientName;
	public $tmstitle;
	public $tmsmessage;

	public $subClientName;
	public $subClientCode;
	public $viewDT;
	public $completeDT;
	public $verifyDT;
  public $appUseYN;
  public $tx_id;

  public function fromJsonInfo($jsonInfo)
  {
    isset($jsonInfo->receiptID) ? $this->receiptID = $jsonInfo->receiptID : null;
    isset($jsonInfo->regDT) ? $this->regDT = $jsonInfo->regDT : null;
    isset($jsonInfo->state) ? $this->state = $jsonInfo->state : null;

    isset($jsonInfo->expires_in) ? $this->expires_in = $jsonInfo->expires_in : null;
    isset($jsonInfo->callCenterNum) ? $this->callCenterNum = $jsonInfo->callCenterNum : null;

    isset($jsonInfo->allowSimpleRegistYN) ? $this->allowSimpleRegistYN = $jsonInfo->allowSimpleRegistYN : null;
    isset($jsonInfo->verifyNameYN) ? $this->verifyNameYN = $jsonInfo->verifyNameYN : null;
    isset($jsonInfo->payload) ? $this->payload = $jsonInfo->payload : null;
    isset($jsonInfo->requestDT) ? $this->requestDT = $jsonInfo->requestDT : null;
    isset($jsonInfo->expireDT) ? $this->expireDT = $jsonInfo->expireDT : null;
    isset($jsonInfo->clientCode) ? $this->clientCode = $jsonInfo->clientCode : null;
    isset($jsonInfo->clientName) ? $this->clientName = $jsonInfo->clientName : null;
    isset($jsonInfo->tmstitle) ? $this->tmstitle = $jsonInfo->tmstitle : null;
    isset($jsonInfo->tmsmessage) ? $this->tmsmessage = $jsonInfo->tmsmessage : null;

    isset($jsonInfo->subClientName) ? $this->subClientName = $jsonInfo->subClientName : null;
    isset($jsonInfo->subClientCode) ? $this->subClientCode = $jsonInfo->subClientCode : null;
    isset($jsonInfo->viewDT) ? $this->viewDT = $jsonInfo->viewDT : null;
    isset($jsonInfo->completeDT) ? $this->completeDT = $jsonInfo->completeDT : null;
    isset($jsonInfo->verifyDT) ? $this->verifyDT = $jsonInfo->verifyDT : null;
    isset($jsonInfo->appUseYN) ? $this->appUseYN = $jsonInfo->appUseYN : null;
    isset($jsonInfo->tx_id) ? $this->tx_id = $jsonInfo->tx_id : null;


  }
}

?>
