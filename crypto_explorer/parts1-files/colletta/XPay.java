package it.colletta.payment;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import com.mortbay.iwiki.User;

import it.colletta.Configuration;
import it.colletta.reservation.ReservationData;
import it.colletta.reservation.ReservationManager;

public class XPay 
{

    public enum ResponseCode
    {
        CODE_0("0", "Autorizzazione concessa"),
        CODE_20("20", "Ordine non presente"),
        CODE_101("101", "Parametri errati or mancanti"),
        CODE_102("102", "PAN errato"),
        CODE_103("103", "Autorizzazione negata dall'emittente della carta"),
        CODE_104("104", "Errore generico"),
        CODE_108("108", "Ordine gia registrato"),
        CODE_109("109", "Errore tecnico"),
        CODE_110("110", "Numero contratto gia presente"),
        CODE_111("111", "Mac errato"),
        CODE_112("112", "Transazione negata per autenticazione VBV o SC fallita o non possiblile"),
        CODE_113("113", "Numero contratto non presente in archivio"),   
        CODE_114("114","Merchant non abilitato al pagamento multipo sul gruppo"),
        CODE_115("115","Codice gruppo non presente"),
        CODE_116("116", "3D secure annullato da utente"),
        CODE_117("117", "Carta non autorizzata causa applicazione regole BIN Table"),
        CODE_118("118", "Controllo Blacklist"),
        CODE_119("119", "Esercente non abilitato ad operare in questa modalita"),
        CODE_120("120", "Circuito non accettato"), 
        CODE_121("121", "Transazione chiusa per timeout"),
        CODE_122("122", "Numera di tentativi di retry esauriti"),
        CODE_400("400", "Auth denied"),
        CODE_401("401", "Expired card"),
        CODE_402("402", "Restricted card"),
        CODE_403("403", "Invalid merchant"),
        CODE_404("404", "Transaction not permitted"),
        CODE_405("405", "Insufficient funds"),
        CODE_406("406", "Technical problem"),
        CODE_407("407", "Host not found");
        
        private final String _code;
        private final String _reason;
        
        ResponseCode(String code, String reason)
        {
            _code = code;
            _reason = reason;
        }

        public String getCode()
        {
            return _code;
        }

        public String getReason()
        {
            return _reason;
        }
        
        public String toString()
        {
            return _code+":"+_reason;
        }
    }

    
    public enum Language 
    {
        ITALIAN("IT", "ITA"),
        ENGLISH("EN", "ENG"),
        FRENCH("FR", "FRA"),
        GERMAN("DE", "GER");
        
        private final String _xpay;
        private final String _ours;
        
        Language(String ours, String theirs)
        {
            _ours = ours;
            _xpay = theirs;
        }
        
        public String ours()
        {
            return _ours;
        }
        
        public String theirs()
        {
            return _xpay;
        }
    }
    
    public static Map<String, String> __ourLanguageToTheirs;
    public static Map<String, ResponseCode> __responseCodes;
     
    public static final String PAYMENT_URL_PROP = "PAYMENT_URL"; //used by XPay.tag file
    
    private static final String MAC_SECRET; //our mac secret key
    private static final String ALIAS_VALUE; //our merchant id
    private static final String URL_BACK_VALUE; //url on our site to return to if payment cancelled or errored
    private static final String URL_VALUE; //url on our site to return to after payment
    private static final String NOTIFICATION_URL_VALUE; //our url to which xpay does a POST to confirm payment
    private static final String PAYMENT_URL_VALUE; //url for xpay payments on cartasi site
    
    /*
     * Fields for messages SENT to XPAY
     * 
     * Message example 1: EU50 payment
     * https://ecommerce.cartasi.it/ecomm/ecomm/DispatcherServlet?alias=valore
     *         &importo=5000
     *         &divisa=EUR
     *         &codTrans=990101-00001
     *         &mail=xxx@xxxx.it
     *         &url=http://www.xxxxx.it
     *         &session_id=xxxxxxxx
     *         &mac=yyyy
     *         &languageId=ITA
     *         
     * Message example 2: EU50,12 payment
     * https://ecommerce.cartasi.it/ecomm/ecomm/DispatcherServlet?alias=valore
     *         &importo=5012
     *         &divisa=EUR
     *         &codTrans=990101-00001
     *         &mail=xxx@xxxx.it
     *         &url=http://www.xxxxx.it
     *         &session_id=xxxxxxxx
     *         &mac=yyyy
     *         &languageId=ENG
     */
    public static final String ALIAS = "alias";           //identifies merchant
    public static final String IMPORTO = "importo";       //amount
    public static final String DIVISA = "divisa";         //currency, only EUR
    public static final String COD_TRANS = "codTrans";    //unique transaction id, can't contain #
    public static final String URL = "url";               //our url to return user after paying
    public static final String URL_BACK = "url_back";     //our url if cancelled/error
    public static final String URL_POST = "urlpost";      //our url for confirmation of payment via POST
    public static final String MAC = "mac";               //calculated mac
    public static final String MAIL = "mail";             //email of renter
    public static final String LANGUAGE_ID = "languageId";//code for language of renter
    public static final String SESSION_ID = "session_id"; //session id of renter
    public static final String OPTION_CF = "OPTION_CF";   //codice fiscale of renter
    public static final String TCONTAB = "TCONTAB";       //I = immediate
    
    

    /*
     * Fields for messages RECEIVED from XPAY
     */
    public static final String BRAND = "brand";           //type of card used to pay
    public static final String DATA = "data";             //yyyymmdd date of completed transaction
    public static final String ORARIO = "orario";         //hhmmss time of completed transaction
    public static final String COD_AUT = "codAut";        //auth code from card on success
    public static final String ESITO = "esito";           //OK|KO for urlpost, or ANNULLO|ERRORE for url_back
    public static final String CODICE_ESITO = "codiceEsito"; //3 chars
    

    public static final String ANNULLO = "ANNULLO";
    public static final String ERRORE = "ERRORE";
    public static final String OK = "OK";
    public static final String KO = "KO";


    private static final List idtransList;/* list of already processed transaction ids*/
    
    
  
    /* Initialize static data */
    static
    {
        MAC_SECRET = Configuration.getInstance().getProperty("xpay.mackey");
        ALIAS_VALUE = Configuration.getInstance().getProperty("xpay.alias"); 
        
        PAYMENT_URL_VALUE = Configuration.getInstance().getProperty("xpay.paymenturl");
        URL_VALUE = Configuration.getInstance().getProperty("colletta.website")+Configuration.getInstance().getProperty("xpay.resulturl");
        URL_BACK_VALUE = Configuration.getInstance().getProperty("colletta.website")+Configuration.getInstance().getProperty("xpay.errorurl");
        NOTIFICATION_URL_VALUE = Configuration.getInstance().getProperty("colletta.website")+Configuration.getInstance().getProperty("xpay.notificationurl");

        idtransList = new ArrayList();
        
        __ourLanguageToTheirs = new HashMap<String, String>();
        __ourLanguageToTheirs.put(Language.ITALIAN.ours(), Language.ITALIAN.theirs());
        __ourLanguageToTheirs.put(Language.FRENCH.ours(), Language.FRENCH.theirs());
        __ourLanguageToTheirs.put(Language.ENGLISH.ours(), Language.ENGLISH.theirs());
        __ourLanguageToTheirs.put(Language.GERMAN.ours(), Language.ITALIAN.theirs());

        __responseCodes = new HashMap<String, ResponseCode>();
        __responseCodes.put(ResponseCode.CODE_0.getCode(),ResponseCode.CODE_0);
        __responseCodes.put(ResponseCode.CODE_20.getCode(),ResponseCode.CODE_20);
        __responseCodes.put(ResponseCode.CODE_101.getCode(),ResponseCode.CODE_101);
        __responseCodes.put(ResponseCode.CODE_102.getCode(),ResponseCode.CODE_102);
        __responseCodes.put(ResponseCode.CODE_103.getCode(),ResponseCode.CODE_103);
        __responseCodes.put(ResponseCode.CODE_104.getCode(),ResponseCode.CODE_104);
        __responseCodes.put(ResponseCode.CODE_108.getCode(),ResponseCode.CODE_108);
        __responseCodes.put(ResponseCode.CODE_109.getCode(),ResponseCode.CODE_109);
        __responseCodes.put(ResponseCode.CODE_110.getCode(),ResponseCode.CODE_110);
        __responseCodes.put(ResponseCode.CODE_111.getCode(),ResponseCode.CODE_111);
        __responseCodes.put(ResponseCode.CODE_112.getCode(),ResponseCode.CODE_112);
        __responseCodes.put(ResponseCode.CODE_113.getCode(),ResponseCode.CODE_113);
        __responseCodes.put(ResponseCode.CODE_114.getCode(),ResponseCode.CODE_114);
        __responseCodes.put(ResponseCode.CODE_115.getCode(),ResponseCode.CODE_115);
        __responseCodes.put(ResponseCode.CODE_116.getCode(),ResponseCode.CODE_116);
        __responseCodes.put(ResponseCode.CODE_117.getCode(),ResponseCode.CODE_117);
        __responseCodes.put(ResponseCode.CODE_118.getCode(),ResponseCode.CODE_118);
        __responseCodes.put(ResponseCode.CODE_119.getCode(),ResponseCode.CODE_119);
        __responseCodes.put(ResponseCode.CODE_120.getCode(),ResponseCode.CODE_120);
        __responseCodes.put(ResponseCode.CODE_121.getCode(),ResponseCode.CODE_121);
        __responseCodes.put(ResponseCode.CODE_122.getCode(),ResponseCode.CODE_122);
        __responseCodes.put(ResponseCode.CODE_400.getCode(),ResponseCode.CODE_400);
        __responseCodes.put(ResponseCode.CODE_401.getCode(),ResponseCode.CODE_401);
        __responseCodes.put(ResponseCode.CODE_402.getCode(),ResponseCode.CODE_402);
        __responseCodes.put(ResponseCode.CODE_403.getCode(),ResponseCode.CODE_403);
        __responseCodes.put(ResponseCode.CODE_404.getCode(),ResponseCode.CODE_404);
        __responseCodes.put(ResponseCode.CODE_405.getCode(),ResponseCode.CODE_405);
        __responseCodes.put(ResponseCode.CODE_406.getCode(),ResponseCode.CODE_406);
        __responseCodes.put(ResponseCode.CODE_407.getCode(),ResponseCode.CODE_407);
    }


    /**
     * Just get the reservation id from the payment message.
     * 
     * @param srequest
     * @param context
     * @return the reservation id
     * @throws Exception
     */
    public static String getResIdFromPaymentMessage (HttpServletRequest srequest, ServletContext context)
    throws Exception
    {
        User old=User.getCurrentUser();
        User.setCurrentUser(User.XPAY);
        
        String transactionId = srequest.getParameter(COD_TRANS);                   
        return getResIdFromTransactionId(transactionId);
    }

    
    /**
     * Called when the user has cancelled, errored or been successful with
     * a payment. There are different params sent in each case.
     * 
     * @param srequest
     * @param context
     * @return
     * @throws Exception
     */
    public static String handlePayment (HttpServletRequest srequest, ServletContext context)
    throws Exception
    {
        User old=User.getCurrentUser();
        User.setCurrentUser(User.XPAY);
        try
        {
            //Verify that the payment confirmation message is authentic, if it contains a MAC
            if ((null != srequest.getParameter(MAC)) && !verifyReceivedMAC(srequest))
            {
                //authentication of the message failed, log it
                context.log ("AUTH FAILED for XPAY: "+srequest.toString());
                return null;
            }
            
            String transactionId = srequest.getParameter(COD_TRANS);                   
            ReservationManager resMgr = ReservationManager.getInstance();
            synchronized (idtransList) 
            {
                //check if this payment message has been received before
                if (idtransList.contains(transactionId))
                {
                    //log duplicate message
                    context.log ("Ignoring duplicate payment confirmation message transactionId="+transactionId);
                    return getResIdFromTransactionId(transactionId);
                }
                else
                {
                    //payment message not already received
                    idtransList.add(transactionId);
                                       
                    String resId = getResIdFromTransactionId(transactionId);
                    
                    String esito = srequest.getParameter(ESITO);
                    
                    //if we are called as the URL_BACK it is only with cancellation or error
                    if (ANNULLO.equalsIgnoreCase(esito) || ERRORE.equalsIgnoreCase(esito))
                    {
                        String tmp = srequest.getParameter(CODICE_ESITO);
                        ResponseCode code = (tmp != null?__responseCodes.get(tmp):null);
                        context.log ("Error or cancelled payment for res "+resId+"."+(code == null?"":code.toString()));
                        return resId;
                    }
                    
                    //if we are called as the URL (with GET) or URL_POST(with POST)
                    if (KO.equalsIgnoreCase(esito))
                    {
                        String tmp = srequest.getParameter(CODICE_ESITO);
                        ResponseCode code = (tmp != null?__responseCodes.get(tmp):null);
                        context.log ("Error in payment for res "+resId+"."+(code == null?"":code.toString()));
                        return resId;
                    }

                    //otherwise it is a successful payment
                    String brand = srequest.getParameter(BRAND);
                    String data = srequest.getParameter(DATA);
                    String orario = srequest.getParameter(ORARIO);
                    String codAut = srequest.getParameter(COD_AUT);
                    String importo = srequest.getParameter(IMPORTO);

                    ReservationData reservation=resMgr.findReservation(resId);
                    if (reservation==null)
                        throw new Exception ("Cannot make payment transactionId="+transactionId+": no such reservation resId="+resId);

                    
                    importo = importo.substring(0, importo.length()-2) + "." + importo.substring(importo.length()-2);
                    BigDecimal amount = new BigDecimal(importo);    
                    resMgr.makePayment(resId,amount,transactionId+", "+brand+", "+codAut);

                    context.log ("PAYMENT PROCESSED: resId="+resId+" for amount(EUR)="+importo+" by "+brand+" auth code="+codAut+" on "+data+" at "+orario);
                    return resId;
                }
            }  
        }
        finally
        {
            User.setCurrentUser(old);
        }     
    }


    
    
    public static void setPaymentAttributes (HttpServletRequest request, String resId, BigInteger amount, String lang, String email)
    throws Exception
    {
        String transactionId = makeTransactionIdFromResId (resId);
        request.setAttribute(URL, URL_VALUE);
        request.setAttribute(URL_BACK, URL_BACK_VALUE);
        request.setAttribute(PAYMENT_URL_PROP, PAYMENT_URL_VALUE);
        request.setAttribute(URL_POST, NOTIFICATION_URL_VALUE);
        request.setAttribute(ALIAS, ALIAS_VALUE);
        request.setAttribute(IMPORTO, amount.toString());
        request.setAttribute(COD_TRANS, transactionId);
        request.setAttribute(MAIL, email);
        request.setAttribute(LANGUAGE_ID, convertLanguage(lang));
        request.setAttribute(MAC, getSendingMAC(request));    
    }
    
    
    public static void dumpPaymentAttributes (HttpServletRequest request)
    {
        System.err.println("to:"+request.getAttribute(PAYMENT_URL_PROP));
        System.err.println("return url:"+request.getAttribute(URL));
        System.err.println("fail url:"+request.getAttribute(URL_BACK));
        System.err.println("alias:"+request.getAttribute(ALIAS));
        System.err.println("importo:"+request.getAttribute(IMPORTO));
        System.err.println("codTrans:"+request.getAttribute(COD_TRANS));
        System.err.println("email:"+request.getAttribute(MAIL));
        System.err.println("lang:"+request.getAttribute(LANGUAGE_ID));
        System.err.println("mac:"+request.getAttribute(MAC));
    }
    
    public static String makeTransactionIdFromResId (String resId)
    throws Exception
    {
        ReservationData rd = ReservationManager.getInstance().findReservation(resId);
        if (rd == null)
            throw new IllegalStateException("Unknown reservation: "+resId);
      
        //Make a unique id by appending ms since epoch as alpha string
        String str = (resId+"-"+Long.toString(System.currentTimeMillis(), 36));      
       
        return str;
    }
    
    
    public static String getResIdFromTransactionId (String transId)
    {
        if (transId == null)
            throw new IllegalStateException ("No transaction id");
        transId = transId.trim();
        if ("".equals(transId))
            throw new IllegalStateException ("No transaction id");
        
        String resId = transId;
        int i = resId.indexOf("-");
        
        //Get rid of appended ms
        if (i >= 0)
            resId = resId.substring(0,i);
        
        //Get last 8 chars, which is the zero-padded reservation id
        if (resId.length() > 8)
            resId = resId.substring(resId.length()-8);
        
        return resId;
    }
    
    /**
     * Generate a MAC string.
     * 
     * @param request
     * @return
     * @throws Exception
     */
    public static String getSendingMAC (HttpServletRequest request)
    throws Exception
    {
        StringBuffer buff = new StringBuffer();
        String tmp = (String)request.getAttribute(COD_TRANS);
        buff.append(COD_TRANS+"="+tmp);
        buff.append(DIVISA+"=EUR"); //unchangeable
        tmp = (String)request.getAttribute(IMPORTO);
        buff.append(IMPORTO+"="+tmp);
        buff.append(MAC_SECRET);

        return calculateMAC (buff.toString());
    }
    
    /**
     * Generate a MAC string from a message received from Xpay.
     * 
     * Uses fields:
     * <ol>
     * <li>codTrans</li>
     * <li>esito</li>
     * <li>importo</li>
     * <li>divisa</li>
     * <li>data</li>
     * <li>orario</li>
     * <li>codAut</li>
     * <li>mac key</li>
     * </ol>
     * @param request
     * @return
     * @throws Exception
     */
    public static String getReceivingMAC (HttpServletRequest request)
    throws Exception
    {
        StringBuffer buff = new StringBuffer();
        String tmp = (String)request.getParameter(COD_TRANS);
        buff.append(COD_TRANS+"="+tmp);
        tmp = (String)request.getParameter(ESITO);
        buff.append(ESITO+"="+tmp);
        tmp = (String)request.getParameter(IMPORTO);
        buff.append(IMPORTO+"="+tmp);
        tmp = (String)request.getParameter(DIVISA);
        buff.append(DIVISA+"="+tmp);
        tmp = (String)request.getParameter(DATA);
        buff.append(DATA+"="+tmp);
        tmp = (String)request.getParameter(ORARIO);
        buff.append(ORARIO+"="+tmp);
        //buff.append(ORARIO+tmp);
        tmp = (String)request.getParameter(COD_AUT);
        buff.append(COD_AUT+"="+tmp);
        buff.append(MAC_SECRET);
        
        return calculateMAC(buff.toString());
    }
    
    public static String calculateMAC (String str) 
    throws Exception
    {
        if (str == null)
            return null;
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        digest.update (str.getBytes("UTF-8"));
        return  toHexString(digest.digest());    
    }
    

    
    /**
     * Check the mac sent by XPay matches the mac we calculate
     * from the message.
     * 
     * @param request
     * @return
     */
    public static boolean verifyReceivedMAC (HttpServletRequest request)
    throws Exception
    {
        String mac = request.getParameter(MAC);
        String calculatedMac = getReceivingMAC(request);
        if (mac != null && mac.equals(calculatedMac))
            return true;
        
        return false;
    }

    
    public static String convertLanguage (String siteLang)
    {
        if (siteLang == null)
            return Language.ENGLISH.theirs();
        String s = siteLang.trim();
        if ("".equals(s))
            return Language.ENGLISH.theirs();
        
        String theirs = __ourLanguageToTheirs.get(s);
        if (theirs == null)
            return Language.ENGLISH.theirs();
        
        return theirs;
    }

    /**
     * Convert hashed value from bytes to hex string (uppercase)
     * @param bytes
     * @return
     */
    private static String toHexString (byte[] b)
    {
        char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuffer buf = new StringBuffer();
        for (int j=0; j<b.length; j++) {
            buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
            buf.append(hexDigit[b[j] & 0x0f]);
        }
        return buf.toString();
    }
}
