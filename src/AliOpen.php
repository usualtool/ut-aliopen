<?php
namespace usualtool\AliOpen;
/**
 * 通用签名接口
 */
class AliOpen{
    var $appid;
    var $appkey;
    var $alikey;
    var $appline;
    public function __construct($appid,$appkey,$alikey,$appline="https://openapi.alipay.com/gateway.do?charset=utf-8"){
        $this->appid=$appid;
        $this->appkey=$appkey;
        $this->alikey=$alikey;
        $this->appline=$appline;
    }
    public function AddSign($data,$type='RSA2') {
        $src=(string)$this->appkey;
        if(trim($src)===""){
            throw new \RuntimeException('支付宝应用私钥为空');
        }
        if(strpos($src,'PRIVATE KEY')===false){
            $der=base64_decode(preg_replace('/\s+/','',$src));
            $isPkcs8 = (substr($der,7,3)==="30\x0d\x06");
            $begin = $isPkcs8 ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN RSA PRIVATE KEY-----';
            $end   = $isPkcs8 ? '-----END PRIVATE KEY-----' : '-----END RSA PRIVATE KEY-----';
            $src=$begin.$src.$end;
        }
        $isPkcs8 = strpos($src,'BEGIN PRIVATE KEY')!==false;
        $begin = $isPkcs8 ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN RSA PRIVATE KEY-----';
        $end   = $isPkcs8 ? '-----END PRIVATE KEY-----' : '-----END RSA PRIVATE KEY-----';
        $body=str_replace(array($begin,$end,"\n","\r"," ","\t"),'',$src);
        $private_key=$begin . PHP_EOL . wordwrap($body, 64, "\n", true) . PHP_EOL . $end;
        $res=openssl_get_privatekey($private_key);
        if($res){
            if($type == 'RSA'){
                openssl_sign($data, $sign,$res);
            }elseif($type == 'RSA2'){
                openssl_sign($data, $sign,$res,OPENSSL_ALGO_SHA256);
            }
        }else {
            throw new \RuntimeException('支付宝应用私钥格式有误（PEM 或裸 base64 均无法解析）');
        }
        $sign = base64_encode($sign);
        return $sign;
    }
    public function ChkSign($data,$sign,$type='RSA2')  {
        $search = [
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            "\n",
            "\r",
            "\r\n"
        ];
        $public_key=str_replace($search,"",$this->alikey);
        $public_key=$search[0] . PHP_EOL . wordwrap($public_key, 64, "\n", true) . PHP_EOL . $search[1];
        $res=openssl_get_publickey($public_key);
        if($res){
            if($type == 'RSA'){
                $result = (bool)openssl_verify($data, base64_decode($sign), $res);
            }elseif($type == 'RSA2'){
                $result = (bool)openssl_verify($data, base64_decode($sign), $res,OPENSSL_ALGO_SHA256);
            }
        }else{
            throw new \RuntimeException('支付宝公钥格式有误（配置里填的不是 PEM 公钥）');
        }
        return $result;
    }
    public function GetPin($method,$bizstr,$type=''){
        if(!empty($type)){
            $bizstrv=urlencode($bizstr);
        }else{
            $bizstrv=$bizstr;
        }
        if(is_array($bizstr)){
            $arr=array_merge(array("timestamp"=>date('Y-m-d H:i:s',time()),
            "app_id"=>$this->appid,
            "method"=>$method,
            "format"=>"json",
            "charset"=>"utf-8",
            "sign_type"=>"RSA2",
            "version"=>"1.0"),$bizstrv);
        }else{
        $arr=array("timestamp"=>date('Y-m-d H:i:s',time()),
            "app_id"=>$this->appid,
            "method"=>$method,
            "format"=>"json",
            "charset"=>"utf-8",
            "sign_type"=>"RSA2",
            "version"=>"1.0",
            "biz_content"=>$bizstrv);
        }
        return $arr;
    }
    public function GetStr($arr,$type = 'RSA2'){
        if(isset($arr['sign'])){
            unset($arr['sign']);
        }
        if(isset($arr['sign_type']) && $type == 'RSA'){
            unset($arr['sign_type']);
        }
        ksort($arr);
        return$this->GetUrl($arr,false);
    }
    public function GetUrl($arr,$encode = true){
        if($encode){
            return http_build_query($arr);
        }else{
            return urldecode(http_build_query($arr));
        }
    }
    public function GetSign($arr){
        $signstr=md5($this->GetStr($arr));
        return $signstr;
    }
    public function SetSign($arr){
        $arr['sign'] = $this->GetSign($arr);
        return $arr;
    }
    public function GetRsaSign($arr){
        return $this->AddSign($this->getStr($arr),'RSA') ;
    }
    public function SetRsaSign($arr){
        $arr['sign'] = $this->GetRsaSign($arr);
        return $arr;
    }
    public function GetRsa2Sign($arr){
        return $this->AddSign($this->GetStr($arr,'RSA2'),'RSA2') ;
    }
    public function SetRsa2Sign($arr){
        $arr['sign'] = $this->GetRsa2Sign($arr);
        return $arr;
    }
    public function CheckSign($arr){
        $sign = $this->GetSign($arr);
        if($sign == $arr['sign']){
            return true;
        }else{
            return false;
        }
    }
    /**
     * 授权码换访问令牌
     */
    public function GetOauthToken($code){
        $out=json_decode($this->ApiRequest("alipay.system.oauth.token",array("grant_type"=>"authorization_code","code"=>$code)),true);
        if(isset($out["code"]) && empty($out["access_token"])){
            throw new \RuntimeException($out["sub_msg"] ?? ($out["msg"] ?? "支付宝网关返回错误"));
        }
        return $out;
    }
    /**
     * 访问令牌取会员信息
     */
    public function GetUserInfo($accessToken){
        $out=json_decode($this->ApiRequest("alipay.user.info.share",array("auth_token"=>$accessToken)),true);
        if(isset($out["code"]) && empty($out["user_id"]) && empty($out["open_id"])){
            throw new \RuntimeException("换取用户信息失败：".($out["sub_msg"] ?? ($out["msg"] ?? "网关未返回用户标识")));
        }
        if(empty($out["user_id"]) && !empty($out["open_id"])){
            $out["user_id"]=$out["open_id"];
        }
        return $out;
    }
    /**
     * 授权码换用户标识
     */
    public function GetUser($code){
        $token=$this->GetOauthToken($code);
        if(!empty($token["user_id"])){
            $token["source"]="oauth";
            return $token;
        }
        if(empty($token["access_token"])){
            throw new \RuntimeException("oauth.token 未返回 access_token/user_id，返回键：".implode(",",array_keys($token)));
        }
        $info=$this->GetUserInfo($token["access_token"]);
        $info["access_token"]=$token["access_token"];
        return $info;
    }
    public function ApiRequest($method,$bizstr){
        if(is_array($bizstr)){
            $params=$this->GetPin($method,$bizstr);
        }else{
            $params=$this->GetPin($method,$bizstr,1);
            $params["biz_content"]=urldecode($params["biz_content"]);
        }
        $sign=$this->AddSign($this->GetStr($params),'RSA2');
        $params["sign"]=$sign;
        $pairs=array();
        foreach($params as $k=>$v){
            $pairs[]=rawurlencode($k)."=".rawurlencode((string)$v);
        }
        $pastr=implode("&",$pairs);
        $curl = curl_init();
        $header = array('content-type:application/x-www-form-urlencoded;charset=utf-8');
        curl_setopt($curl,CURLOPT_HTTPHEADER,$header);
        curl_setopt($curl, CURLOPT_URL, $this->appline);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS,$pastr);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        $raw = curl_exec($curl);
        $errno = curl_errno($curl);
        $error = curl_error($curl);
        if(PHP_VERSION_ID<80000){
            curl_close($curl);
        }
        if($errno){
            throw new \RuntimeException('请求支付宝网关失败：'.$error);
        }
        $output = json_decode($raw,true);
        if(is_array($output) && isset($output['error_response'])){
            return json_encode($output['error_response']);
        }
        $node = str_replace(".", "_",$method) . "_response";
        if(!is_array($output) || !isset($output[$node])){
            $snippet = function_exists('mb_substr') ? mb_substr((string)$raw,0,200) : substr((string)$raw,0,200);
            if(!preg_match('//u',$snippet)){
                $snippet = bin2hex(substr((string)$raw,0,60));
            }
            throw new \RuntimeException('支付宝网关返回异常：'.$snippet);
        }
        return json_encode($output[$node]);
    }
}
