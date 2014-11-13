/**
 *
 */
package controllers

import play.api._
import play.api.mvc._
import play.api.libs.ws._
import scala.concurrent.duration._
import Application._
import java.util.UUID
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import akka.util.Timeout
import scala.concurrent.duration._
import java.net.URLEncoder
import com.ning.http.client.oauth.ConsumerKey

/**
 * @author vsingh12
 *
 */
object QBOSample extends Controller {

  val sandboxQBOEndpoint = "https://sandbox-quickbooks.api.intuit.com/v3";
  val prodQBOEndpoint = "https://quickbooks.api.intuit.com";

  val sandboxPaymentsEndpoint = "https://sandbox.api.intuit.com/quickbooks/v4/payments";
  //val prodPaymentsEndpoint = "https://api.intuit.com"; // Need to check this value

  val sandboxPaymentsStageEndpoint = "";
  val prodPaymentsStageEndpoint = "https://e2e.api.intuit.com/quickbooks/v4/payments";

  def getCustomer = Action {

    var oauth_nonce = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;

    val signatureBaseString = "GET&https%3A%2F%2Fqb.sbfinance.intuit.com%2Fv3%2Fcompany%2F1290883070%2Fcustomer%2F2&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

    val secret = new SecretKeySpec((consumerSecret + "&" + accessSecret).getBytes, "HmacSHA1")
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret)
    val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
    val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
    val headers = ("Authorization" -> ("""OAuth oauth_consumer_key="""" + consumerKey + """", 
              oauth_nonce="""" + oauth_nonce + """", 
              oauth_signature="""" + URLEncoder.encode(signature) + """", 
              oauth_signature_method="HMAC-SHA1", 
              oauth_timestamp="""" + timestamp + """", 
              oauth_token="""" + accessToken + """", 
              oauth_version="1.0" """))

    println("------> Tokens : " + accessToken + "," + accessSecret)
    println("------> SignatureBaseSTring : " + signatureBaseString)
    println("------> Headers : " + headers)

    val requestHolder = WS.url("https://qb.sbfinance.intuit.com/v3/company/" + Application.realmId + "/customer/2").withHeaders(headers);
    println("-------> Request : " + requestHolder.toString)
    val futureResult: Future[play.api.libs.ws.Response] = requestHolder.get

    implicit val timeout = Timeout(15 seconds)
    val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
    println("-------> Body " + result.body)

    Ok(views.html.index("Your new application is ready."))
  }

  def createCustomer = Action {

    var oauth_nonce = UUID.randomUUID();
    var oauth_request_id = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;
    val url = sandboxQBOEndpoint + "/company/" + realmId + "/customer"; //For e.g. the request URI would be https://sandbox-quickbooks.api.intuit.com/v3/company/1292729422/customer

    val postPayload = """{
   "FamilyName":"Singh"
}"""

    val signatureBaseString = "POST&" + URLEncoder.encode(url) + "&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

    //The signing key(secret) is a combination of the consumerSecret followed by an ampersand followed by the accessSecret
    val secret = new SecretKeySpec((consumerSecret + "&" + accessSecret).getBytes, "HmacSHA1")
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret)
    //Generate a binary value by passing the value(signatureBaseString) and the signing key (secret) through the HMAC-SHA1 algorithm
    val signatureByte: Array[Byte] = mac.doFinal((signatureBaseString).getBytes)
    //Convert the binary value to ASCII text through Base64
    val signature = new sun.misc.BASE64Encoder().encode(signatureByte)
    //Construct the Auth headers to be used for the HTTP request
    val headers = ("Authorization" -> ("""OAuth oauth_consumer_key="""" + consumerKey + """", 
              oauth_nonce="""" + oauth_nonce + """", 
              oauth_signature="""" + URLEncoder.encode(signature) + """", 
              oauth_signature_method="HMAC-SHA1", 
              oauth_timestamp="""" + timestamp + """", 
              oauth_token="""" + accessToken + """", 
              oauth_version="1.0" """))

    println("------> Tokens : " + accessToken + "," + accessSecret)
    println("------> SignatureBaseSTring : " + signatureBaseString)
    println("------> Headers : " + headers)

    val requestHolder = WS.url(url).withHeaders(headers, "Content-Type" -> "application/json");
    println("-------> Request : " + requestHolder.toString)
    val futureResult: Future[play.api.libs.ws.Response] = requestHolder.post(postPayload)

    implicit val timeout = Timeout(15 seconds)
    val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
    println("-------> HTTP status " + result.status)
    println("-------> Body " + result.body)

    Ok(views.html.index("Your new application is ready."))
  }

}