/*
 * schonfeld.david@gmail.com - Java implementation of a group signature scheme
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

package groupsignature.client;

import java.math.BigInteger;
import java.security.MessageDigest;

import groupsignature.elliptic.ECPoint;
import groupsignature.elliptic.EllipticCurve;
import groupsignature.elliptic.secp256r1;
import groupsignature.keys.*;
import groupsignature.server.*;
import groupsignature.signature.Signature;
import groupsignature.utils.Constants;

public class Verifier {

	private IssuingManager issue;
	private OpeningManager open;
	private RevocationManager revoc;
	private Opk opk;
	private Ipk ipk;
	private Rpk rpk;

	/*
	 * Class constructor
	 */
	public Verifier(IssuingManager issue, OpeningManager open,
			RevocationManager revoc) {
		this.issue = issue;
		this.open = open;
		this.revoc = revoc;
		this.opk = this.open.getOpk();
		this.ipk = this.issue.getIpk();
		this.rpk = this.revoc.getRpk();
	}

	/**
	 * Verify the signature
	 * 
	 * @param message
	 * @param signature
	 * 
	 */
	public Boolean verify(String message, Signature signature) {
		System.out.println("\n---------------Verify protocol--------------\n");
		long start = System.currentTimeMillis();
		Boolean valid = false;
		// Catch the fields
		try {
			this.rpk = this.revoc.getRpk();
			EllipticCurve ec = new EllipticCurve(new secp256r1());
			ECPoint E0 = new ECPoint(ec, signature.getE0().getx(), signature
					.getE0().gety());
			ECPoint E1 = new ECPoint(ec, signature.getE1().getx(), signature
					.getE1().gety());
			ECPoint E2 = new ECPoint(ec, signature.getE2().getx(), signature
					.getE2().gety());
			BigInteger ACOM = signature.getACOM();
			BigInteger BCOM = signature.getBCOM();
			BigInteger c = signature.getC();
			BigInteger taux = signature.getTx();
			BigInteger taus = signature.getTs();
			BigInteger tauePrime = signature.getTePrime();
			BigInteger taut = signature.getTt();
			BigInteger tauE = signature.getTE();

			// Compute the elements
			BigInteger taue = (c.multiply(Constants.expKe)).add(tauePrime);
			// V0
			ECPoint MinuscE0 = new ECPoint(ec, E0.multiply(c).getx(), E0
					.multiply(c).gety().negate());
			ECPoint tauEG = this.opk.getGenerator().multiply(tauE);
			ECPoint V0 = tauEG.add(MinuscE0);
			// V1
			ECPoint MinuscE1 = new ECPoint(ec, E1.multiply(c).getx(), E1
					.multiply(c).gety().negate());
			ECPoint V1 = this.opk.getGenerator().multiply(taux)
					.add(this.opk.getH1().multiply(tauE)).add(MinuscE1);
			// V2
			ECPoint MinuscE2 = new ECPoint(ec, E2.multiply(c).getx(), E2
					.multiply(c).gety().negate());
			ECPoint V2 = this.opk.getGenerator().multiply(taux)
					.add(this.opk.getH2().multiply(tauE)).add(MinuscE2);
			// Vmpk
			BigInteger a0a1 = (ipk.geta0().modPow(c, ipk.getn()).multiply(ipk
					.geta1().modPow(taux, ipk.getn()))).mod(ipk.getn());
			BigInteger a2A = (ipk.geta2().modPow(taus, ipk.getn())
					.multiply(ACOM.modPow(taue.negate(), ipk.getn()))).mod(ipk
					.getn());
			BigInteger Vmpk = (a0a1.multiply(a2A)).mod(ipk.getn());
			// Vrev
			BigInteger bw = ((rpk.getb().modPow(c, rpk.getl())).multiply(rpk
					.getw().modPow(taut, rpk.getl()))).mod(rpk.getl());
			BigInteger Vrev = (bw.multiply(BCOM.modPow(tauePrime.negate(),
					rpk.getl()))).mod(rpk.getl());
			// Compute hash
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String E = E0.getx().toString() + E0.gety().toString()
					+ E1.getx().toString() + E1.gety().toString()
					+ E2.getx().toString() + E2.gety().toString();
			String V = V0.getx().toString() + V0.gety().toString()
					+ V1.getx().toString() + V1.gety().toString()
					+ V2.getx().toString() + V2.gety().toString();
			String reste = ACOM.toString() + BCOM.toString() + V
					+ Vmpk.toString() + Vrev.toString();
			String string = E + reste + message;
			md.update(string.getBytes("UTF-8"));
			BigInteger cPrime = new BigInteger(1, md.digest());
			System.out.println("c'= " + cPrime);
			System.out.println("c = " + c);
			if (cPrime.compareTo(c) == 0) {
				System.out.println("\nGroup signature checked!");
				valid = true;
			} else {
				System.out.println("\nGroup signature failed...");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		System.out.println("\nExecution time was " + (end - start) + " ms.");
		System.out.println("\n---------------DONE--------------");
		return valid;
	}
}
