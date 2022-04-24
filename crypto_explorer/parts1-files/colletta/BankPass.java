/*
 * This class supports the calculation of BankPass fields for
 * the BankPass payment system.
 *
 */
package it.colletta.payment;

import it.colletta.Configuration;
import it.colletta.reservation.ReservationData;
import it.colletta.reservation.ReservationManager;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import com.mortbay.iwiki.StringUtil;
import com.mortbay.iwiki.User;

/**
 * @author janb
 *
 */
public class BankPass 
{
    public static final String ESITO_SUCCESS = "00";   /* success */
    public static final String ESITO_SYSTEM_REFUSAL = "01"; /* system refused */
    public static final String ESITO_SHOP_DATA_ERROR = "02"; /* error with subscriber config in bankpass */
    public static final String ESITO_COMMUNICATION_ERROR = "03"; /* error talking to credit card system */
    public static final String ESITO_CARD_ISSUER_REFUSAL = "04"; /* card issuer refused */
    public static final String ESITO_NUMBER_ERR = "05"; /* bad card number */
    public static final String ESITO_UNEXPECTED_ERR = "06"; /* unexpected processing error */

    private static final String sendingKey;
    private static final String receivingKey;
    private static final List idtransList;/* list of already processed transaction ids*/
  
    /* Initialize keys used in the text to be hashed */
    static
    {
        sendingKey = Configuration.getInstance().getProperty("bankpass.sendkey");
        receivingKey = Configuration.getInstance().getProperty("bankpass.receivekey");
        idtransList = new ArrayList();
    }
    
 
    
    /**
     * Generate a BankPass field value by MD5 hashing the text and the secret key
     * @param request attributes with the values to use
     * @return
     */
    public static String calculateSendingMAC (HttpServletRequest request)
    throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        String text = "";
       
        text = addField (text, "NUMORD", request.getAttribute("NUMORD"));
        text = addField (text, "IDNEGOZIO", request.getAttribute("IDNEGOZIO"));
        text = addField (text, "IMPORTO", request.getAttribute("IMPORTO"));
        text = addField (text, "VALUTA", request.getAttribute("VALUTA"));
        text = addField (text, "TCONTAB", request.getAttribute("TCONTAB"));
        text = addField (text, "TAUTOR", request.getAttribute("TAUTOR"));        
        text = addField (text, sendingKey);
        digest.update (text.getBytes("UTF-8"));
        
        return toHexString(digest.digest());      
        
    }
    
    /**
     * Calculate a hash of text received from bank and compare it to
     * the BankPass field received from the bank
     * @param request containing params
     * @param hashFromBank
     * @return true if they are the same, false otherwise
     */
    public static boolean compareReceivingMAC (HttpServletRequest request)
    throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        
        String mac = request.getParameter("MAC");
        String numord = request.getParameter("NUMORD");
        String esito = request.getParameter ("ESITO");
        String idnegozio = request.getParameter("IDNEGOZIO");
        String aut = request.getParameter ("AUT");
        String importo = request.getParameter ("IMPORTO");
        String idtrans = request.getParameter ("IDTRANS");
        String val = request.getParameter ("VALUTA");
        String tautor = request.getParameter ("TAUTOR");
        String modpag = request.getParameter ("BPW_MODPAG");
        String carta = request.getParameter ("CARTA");
        String tcontab = request.getParameter ("TCONTAB");
        String transazione = request.getParameter ("BPW_TIPO_TRANSAZIONE");
        
        String text = "";
        text = addField (text, "NUMORD", numord);
        text = addField (text, "IDNEGOZIO", idnegozio);
        text = addField (text, "AUT", aut);
        text = addField (text, "IMPORTO", importo);
        text = addField (text, "VALUTA", val);
        text = addField (text, "IDTRANS", idtrans);
        text = addField (text, "TCONTAB", tcontab);        
        text = addField (text, "TAUTOR", tautor);
        text = addField (text, "ESITO", esito);
        if ((modpag != null) && (!modpag.equals("")))
          text = addField (text, "BPW_MODPAG", modpag);
        if ((transazione != null && (!"".equals(transazione))))
            text = addField (text, "BPW_TIPO_TRANSAZIONE", transazione);
        
        text = addField (text, receivingKey);
              
        digest.update (text.getBytes("UTF-8"));
        String result = toHexString(digest.digest());
        
        return result.equalsIgnoreCase(mac);
    }
    
    
    /** Verify that a message from BankPass is authentic.
     * This is done by calculating an MD5 hash of the request params.
     * NOTE that if the message is a payment failure message, BankPass does
     * not send a MAC, so we can't authenticate it.
     * @param request
     * @throws Exception
     */
    public static void verifyPaymentMsg (HttpServletRequest request)
    throws Exception
    {                      
        /* if the operation did not succeed, then the mac is not to be calculated */
        if (ESITO_SUCCESS.equals(request.getParameter("ESITO")))
        {
            if (!compareReceivingMAC (request))
            {
                throw new Exception ("Authentication error: received MAC="+request.getParameter("MAC")+" does not match calculated MAC");
            }
        }
        else
            return; /*no authentication possible, as payment failed so MAC is sent */
    }
    
    
    /** Handle a payment message from BankPass.
     * This involves authenticating the message
     * @param srequest
     * @param context
     * @throws Exception
     */
    public static void handlePayment (HttpServletRequest srequest, ServletContext context)
    throws Exception
    {
        User old=User.getCurrentUser();
        User.setCurrentUser(User.BANKPASS);
        try
        {  
            //Verify that the payment confirmation message is authentic
            BankPass.verifyPaymentMsg (srequest);
            
            String esito = srequest.getParameter("ESITO");
            String valuta = srequest.getParameter ("VALUTA");
            String importo = srequest.getParameter ("IMPORTO");
            String idtrans = srequest.getParameter ("IDTRANS");
            String numord = srequest.getParameter ("NUMORD");
            
            
            if (esito == null || !ESITO_SUCCESS.equals(esito))
            {
                /* payment was a failure, nothing to do but log it */
                context.log ("PAYMENT FAILED: resId="+numord+" esito="+esito+" for amount(ISO"+valuta+")="+importo);
                return;
            }
            
            /* The payment succeeded, so process it */
            ReservationManager resMgr = ReservationManager.getInstance();
            synchronized (idtransList) 
            {
                //check if this payment message has been received before
                if (idtransList.contains(idtrans))
                {
                    //log duplicate message
                    context.log ("Ignoring duplicate payment confirmation message resId="+numord+" idtrans="+idtrans);
                }
                else
                {
                    //payment message not already received, process the payment
                    idtransList.add(idtrans);
                    
                    if (valuta.equals("978"))
                    {	
                        
                        String resId = numord;
                        int i = resId.indexOf("-");
                        if (i >= 0)
                            resId = resId.substring(0,i);
                        
                        ReservationData reservation=resMgr.findReservation(resId);
                        if (reservation==null)
                        {
                            throw new Exception ("Cannot make payment idtrans="+idtrans+" for numord="+numord+": no such reservation resId="+resId);
                        }
                        
                        importo = importo.substring(0, importo.length()-2) + "." + importo.substring(importo.length()-2);
                        BigDecimal amount = new BigDecimal(importo);	
                        resMgr.makePayment(resId,amount,numord+"-"+idtrans);
                        
                        context.log ("PAYMENT PROCESSED: resId="+resId+" esito="+esito+" for amount(ISO"+valuta+")="+importo);
                    }		
                    else
                    {
                        throw new Exception ("Payment was not in EURO");
                    }
                }
            }  
        }
        finally
        {
            User.setCurrentUser(old);
        }     
    }
    
    
    
    /**
     * Convert hashed value from bytes to hex string
     * @param bytes
     * @return
     */
    private static String toHexString (byte[] bytes)
    {
        return StringUtil.toHexString(bytes);
    }
    
    private static String addField (String text, String name, Object value)
    {
        return text + (text.equals("")? "": "&") + name+"="+ (value==null? "NULL" : value.toString());
    }
    
    private static String addField (String text, Object value)
    {
        return text + (text.equals("")? "" : "&") + (value==null? "NULL" : value.toString()); 
    }
   
}
