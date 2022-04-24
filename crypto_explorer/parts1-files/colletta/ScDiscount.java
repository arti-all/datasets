//========================================================================
//$Id: ScDiscount.java,v 1.3 2006/01/21 17:21:00 gregw Exp $
//Copyright 2000-2004 Mort Bay Consulting Pty. Ltd.
//------------------------------------------------------------------------
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at 
//http://www.apache.org/licenses/LICENSE-2.0
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//========================================================================

package it.colletta.reservation.discount;

import it.colletta.Apartment;
import it.colletta.reservation.Adjustment;
import it.colletta.reservation.ReservationData;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.mortbay.iwiki.YyyyMmDd;


/**
 * 
 * Survey Colletta Discount
 *
 * @author janb
 * @version $Revision: 1.3 $ $Date: 2006/01/21 17:21:00 $
 *
 */
public class ScDiscount extends Discount
{
    public final BigDecimal SCONTO=new BigDecimal("-0.08");
   
    public String getName ()
    {
        return "survey";
    }
    
    /** Mamberto agent.
     * @see it.colletta.reservation.discount.Discount#getDescription()
     */
    public String getDescription ()
    {
        return "Survey 8%";
    }

    /** Modify the reservation with any discount that is due
     * @see it.colletta.reservation.discount.Discount#calculate(it.colletta.reservation.ReservationData)
     */
    public boolean calculate (ReservationData res)
    {
        String code=res.getDiscountCode();
        String email=res.getEmail();
        if (code==null || email==null || code.length()==0 || email.length()==0)
            return false;
        
        if (!code.equals(encode(email)))
            return false;
        
        BigDecimal price = res.getPrice();
        BigDecimal sconto = price.multiply(SCONTO);
        sconto=sconto.setScale(2, BigDecimal.ROUND_UP);
        
        res.addAdjustment(Adjustment.__CODE , sconto, "Survey");
        return true;
    }
    
    public static String encode(String email)
    {
        String code=null;
        try
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            code="Survey"+email+"Colletta";
            byte[] b = md.digest(code.getBytes());
            long l = b[0]+(b[1]<<8)+(b[2]<<16)+(b[3]<<24)+(b[4]<<32)+(b[5]<<40)+(b[6]<<48)+(b[7]<<56);
            if (l<0)
                l=-l;
            code = "sc-"+Long.toString(l,36);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        return code;
    }
}
