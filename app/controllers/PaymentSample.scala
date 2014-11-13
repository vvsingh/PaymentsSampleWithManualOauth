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
object PaymentSample extends Controller {

  val sandboxQBOEndpoint = "http://sandbox-quickbooks.api.intuit.com";
  val prodQBOEndpoint = "http://quickbooks.api.intuit.com";

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

  def getCharge = Action {

    var oauth_nonce = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;

    val signatureBaseString = "GET&" + URLEncoder.encode(sandboxPaymentsEndpoint + "/charges/EMU286840680") + "&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

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

    val requestHolder = WS.url(sandboxPaymentsEndpoint + "/charges/EMU286840680").withHeaders(headers);
    println("-------> Request : " + requestHolder.toString)
    val futureResult: Future[play.api.libs.ws.Response] = requestHolder.get

    implicit val timeout = Timeout(15 seconds)
    val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
    println("-------> HTTP status " + result.status)
    println("-------> Body " + result.body)

    Ok(views.html.index("Your new application is ready."))
  }

  def createCharge = Action {

    var oauth_nonce = UUID.randomUUID();
    var oauth_request_id = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;

    val postPayload = """{
    "amount": "10.55",
    "card": {
        "expYear": "2020",
        "expMonth": "02",
        "address": {
            "region": "CA",
            "postalCode": "94086",
            "streetAddress": "1130 Kifer Rd",
            "country": "US",
            "city": "Sunnyvale"
        },
        "name": "emulate=0",
        "cvc": "123",
        "number": "4111111111111111"
    },
    "currency": "USD"
}"""

    val signatureBaseString = "POST&" + URLEncoder.encode(sandboxPaymentsEndpoint + "/charges") + "&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

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

    val requestHolder = WS.url(sandboxPaymentsEndpoint + "/charges").withHeaders(headers, "Request-Id" -> UUID.randomUUID().toString(), "Content-Type" -> "application/json");
    println("-------> Request : " + requestHolder.toString)
    val futureResult: Future[play.api.libs.ws.Response] = requestHolder.post(postPayload)

    implicit val timeout = Timeout(15 seconds)
    val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
    println("-------> HTTP status " + result.status)
    println("-------> Body " + result.body)

    Ok(views.html.index("Your new application is ready."))
  }

  def refundCharge = Action {
    //One thing to remember about refundCharge is that you can only call this API once for a charge. If you try to refund an already refunded charge you will get the following message :
    /*
     * {
    "errors": [
        {
            "code": "PMT-4000",
            "type": "invalid_request",
            "message": "chargeId is invalid.",
            "detail": "chargeId",
            "infoLink": "https://developer.intuit.com/v2/docs?redirectID=PayErrors"
        }
    ]
}
     */
    val chargeIdToRefund = "EMU469093549"
    val chargeAmountToRefund = "10.55"

    var oauth_nonce = UUID.randomUUID();
    var oauth_request_id = UUID.randomUUID();
    var timestamp = System.currentTimeMillis() / 1000;

    val postPayload = """{
    "amount": """" + chargeAmountToRefund + """",
    "description": "first refund",
    "id": """" + chargeIdToRefund + """",
    "context": {}
}"""
    println("Refund Charge POST JSON Payload : " + postPayload)

    val signatureBaseString = "POST&" + URLEncoder.encode(sandboxPaymentsEndpoint + "/charges/" + chargeIdToRefund + "/refunds") + "&oauth_consumer_key%3D" + consumerKey + "%26oauth_nonce%3D" + oauth_nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp + "%26oauth_token%3D" + accessToken + "%26oauth_version%3D1.0";

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

    val requestHolder = WS.url(sandboxPaymentsEndpoint + "/charges/" + chargeIdToRefund + "/refunds").withHeaders(headers, "Request-Id" -> UUID.randomUUID().toString(), "Content-Type" -> "application/json");
    println("-------> Request : " + requestHolder.toString)
    val futureResult: Future[play.api.libs.ws.Response] = requestHolder.post(postPayload)

    implicit val timeout = Timeout(15 seconds)
    val result = Await.result(futureResult, timeout.duration).asInstanceOf[play.api.libs.ws.Response];
    println("-------> HTTP status " + result.status)
    println("-------> Body " + result.body)

    Ok(views.html.index("Your new application is ready."))
  }

}