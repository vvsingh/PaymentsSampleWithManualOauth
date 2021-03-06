package controllers

import play.api._
import play.api.mvc._
import play.api.libs.ws._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import akka.pattern.ask
import akka.util.Timeout
import scala.concurrent.duration._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import java.util.UUID
import java.sql.Timestamp
import play.mvc.Results.Redirect
import java.net.URLEncoder

object Application extends Controller {

  //  //Production endpoints
  val requestTokenURL = "https://oauth.intuit.com/oauth/v1/get_request_token";
  val accessTokenURL = "https://oauth.intuit.com/oauth/v1/get_access_token";
  val userAuthURL = "https://appcenter.intuit.com/Connect/Begin";
  //  

  //Staging endpoints
  //   val requestTokenURL =  "https://oauthws.e2e.qdc.ep.intuit.net/oauth/v1/get_request_token"
  //val accessTokenURL = "https://oauthws.e2e.qdc.ep.intuit.net/oauth/v1/get_access_token"
  //  val userAuthURL = "https://appcenter-stage.intuit.com/Connect/Begin";

  val oauthCallback = "http://localhost:9000/oauthCallbackImpl";

  //Dev (sandbox) Keys for vishav.v.singh+qboe2e8@gmail.com account
  val consumerKey = System.getenv("consumerKey");
  val consumerSecret = System.getenv("consumerSecret");

  var verifier = "";
  var request_token = "";
  var request_token_secret = "";
  var oauth_token = "" //Important to note that this is the same value as the Request Token (the User authorized or denied)
  var oauth_nonce = ""
  var timestamp = ""
  var accessToken = ""
  var accessSecret = ""
  var realmId = ""

  def index = Action {

    request_token = getRequestToken
    println("About to call Redirect()")
    Redirect(userAuthURL + "?oauth_token=" + request_token);
  }

  def getRequestToken: String =
    {
      println("Entering getRequestToken")
      var oauth_nonce = UUID.randomUUID();
      var timestamp = System.currentTimeMillis() / 1000;

      /**
       * CONSTRUCTION OF THE SIGNATURE BASE STRING. NOTE THAT THE PARAMTERS ARE ALPHABETICALLY ORDERED
       */
      val queryString = "?oauth_callback=http%3A%2F%2Flocalhost%3A9000%2FoauthCallbackImpl&oauth_consumer_key=" + consumerKey + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_version=1.0";
      val signatureBaseString = "GET&" + URLEncoder.encode(requestTokenURL) + "&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A9000%252FoauthCallbackImpl%26oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_version%3D1.0";
      println("--->signatureBaseString" + signatureBaseString)
      /**
       * SIGNATURE CALCULATION AND GENERATION FOR REQUEST TOKEN CALL
       * Signing key is "<consumerSecret>&"
       */
      val secret = new SecretKeySpec((consumerSecret + "&").getBytes, "HmacSHA1")
      val mac = Mac.getInstance("HmacSHA1")
      mac.init(secret)
      val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
      //BASE 64 Encode the signature because the result of HMAC-SHA is binary
      val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
      //Append the URL Encoded(v.imp) signature to the end of the Request Token URL along with the query string
      val futureResult: Future[play.api.libs.ws.Response] = WS.url(requestTokenURL + queryString + "&oauth_signature=" + URLEncoder.encode(signature)).get;

      implicit val timeout = Timeout(15 seconds)
      val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];

      println("--------> getRequestToken body" + result.body)
      //Convert result body into Map of key value pairs
      //Example Result : oauth_token_secret=O3wXrEL9wVSz4CbSkIoiVB94v6fm6kFUN6fKs5OI&oauth_callback_confirmed=true&oauth_token=qyprdqstWNGYcfUCxWm5xwttmk0wrt7jzGO8vyKI0lFGlwej
      val mapOfResultBody = result.body.split("&").map(_ split "=") collect { case Array(k, v) => (k, v) } toMap

      request_token_secret = mapOfResultBody("oauth_token_secret").toString()

      println("Quitting getRequestToken")
      mapOfResultBody("oauth_token").toString()

    }

  def getAccessToken =
    {
      println("Entering getAccessToken")
      var oauth_nonce = UUID.randomUUID();
      var timestamp = System.currentTimeMillis() / 1000;

      /**
       * CONSTRUCTION OF THE SIGNATURE BASE STRING. NOTE THAT THE PARAMTERS ARE ALPHABETICALLY ORDERED
       */
      val queryString = "?oauth_consumer_key=" + consumerKey + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + timestamp + "&oauth_token=" + oauth_token + "&oauth_verifier=" + verifier + "&oauth_version=1.0"
      val signatureBaseString = "GET&" + URLEncoder.encode(accessTokenURL) + "&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + oauth_token + "%26oauth_verifier%3D" + verifier + "%26oauth_version%3D1.0"

      /**
       * SIGNATURE CALCULATION AND GENERATION FOR REQUEST TOKEN CALL
       * Signing key is "<consumerSecret>&<oauth_token_secret>"
       */
      val secret = new SecretKeySpec((consumerSecret + "&" + request_token_secret).getBytes, "HmacSHA1")
      val mac = Mac.getInstance("HmacSHA1")
      mac.init(secret)
      val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
      val signature = new sun.misc.BASE64Encoder().encode(signatureByte)

      val futureResult: Future[play.api.libs.ws.Response] = WS.url(accessTokenURL + queryString + "&oauth_signature=" + URLEncoder.encode(signature)).get;

      implicit val timeout = Timeout(15 seconds)
      val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
      val mapOfResultBody = result.body.split("&").map(_ split "=") collect { case Array(k, v) => (k, v) } toMap

      accessToken = mapOfResultBody("oauth_token").toString()
      accessSecret = mapOfResultBody("oauth_token_secret").toString()
      println("getAccessToken response body" + result.body.toString())
      println("Quitting getRequestToken")
    }

  def oauthCallbackImpl = Action { implicit request =>
    println("Entering oauthCallbackImpl")
    verifier = request.getQueryString("oauth_verifier").getOrElse("")
    oauth_token = request.getQueryString("oauth_token").getOrElse("") //Important to note that this is the same value as the Request Token (the User authorized or denied)
    realmId = request.getQueryString("realmId").getOrElse("")
    println("realmId : " + realmId)
    println("Quitting oauthCallbackImpl")

    //Now use this information to get the Access Token
    getAccessToken
    Ok("")

  }

}