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

/**
 * @author vsingh12
 *
 */
object PaymentSample extends Controller {

  val sandboxEndpoint = "http://sandbox-quickbooks.api.intuit.com";
  val prodEndpoint = "http://quickbooks.api.intuit.com";

  def index = Action {

    var oauth_nonce = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;

    val signatureBaseString = "GET&https%3A%2F%2Fqb.sbfinance.intuit.com%2Fv3%2Fcompany%2F1290883070%2Fcustomer%2F2&oauth_consumer_key%3Dqyprd65wBgNHyLYdB7CAzT13AeDMJb%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

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

}