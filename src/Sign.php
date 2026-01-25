<?php
namespace usualtool\Ali;
/**
 * 通用签名接口
 */
class Sign{
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
        $search = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "\n",
            "\r",
            "\r\n"
        ];
        $private_key=str_replace($search,"",$this->appkey);
        $private_key=$search[0] . PHP_EOL . wordwrap($private_key, 64, "\n", true) . PHP_EOL . $search[1];
        $res=openssl_get_privatekey($private_key);
        if($res){
            if($type == 'RSA'){
                openssl_sign($data, $sign,$res);
            }elseif($type == 'RSA2'){
                openssl_sign($data, $sign,$res,OPENSSL_ALGO_SHA256);
            }
            openssl_free_key($res);
        }else {
            exit("私钥格式有误");
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
            openssl_free_key($res);
        }else{
            exit("公钥格式有误");
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
    public function ApiRequest($method,$bizstr){
        $sign=urlencode($this->GetRsa2Sign($this->GetPin($method,$bizstr)));
        if(is_array($bizstr)){
            $pastr=$this->GetStr($this->GetPin($method,$bizstr))."&sign=".$sign;
        }else{
            $pastr=$this->GetStr($this->GetPin($method,$bizstr,1))."&sign=".$sign;
        }
        $curl = curl_init();
        $header = array('content-type:application/x-www-form-urlencoded;charset=utf-8');
        curl_setopt($ch,CURLOPT_HTTPHEADER,$header);
        curl_setopt($curl, CURLOPT_URL, $this->appline);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS,$pastr);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        $output = json_decode(curl_exec($curl),true);
        curl_close($curl);
        $node = str_replace(".", "_",$method) . "_response";
        return json_encode($output[$node]);
    }
}