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

package groupsignature.server;

import groupsignature.elliptic.ECPoint;
import groupsignature.elliptic.EllipticCurve;
import groupsignature.elliptic.secp256r1;
import groupsignature.keys.*;
import groupsignature.signature.Signature;
import groupsignature.utils.Constants;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;

public class OpeningManager implements Serializable {

	private IssuingManager issue;
	private RevocationManager revoc;
	private Opk opk;
	private Osk osk;
	private Ipk ipk;

	public OpeningManager(IssuingManager issue, RevocationManager revoc) {
		System.out
				.println("---------------Setup Opening Manager--------------");
		long start = System.currentTimeMillis();
		this.revoc = revoc;
		this.issue = issue;
		this.ipk = issue.getIpk();
		try {
			// Generation of the Curve
			EllipticCurve ec = new EllipticCurve(new secp256r1());
			// Get the order
			BigInteger q = ec.getOrder();
			// Get the generator point
			ECPoint G = ec.getGenerator();
			// Get y1 and y2
			BigInteger y1 = new BigInteger(q.bitLength(), new Random());
			BigInteger y2 = new BigInteger(q.bitLength(), new Random());
			// Compute H1 and H2
			ECPoint H1 = G.multiply(y1);
			ECPoint H2 = G.multiply(y2);
			// Set keys
			this.opk = new Opk(q, G, H1, H2);
			this.osk = new Osk(y1, y2);
			String print = "\nOpk:\nq = " + this.getOpk().getOrder()
					+ "\nG:\n\tGx = " + this.getOpk().getGenerator().getx()
					+ "\n\tGy = " + this.getOpk().getGenerator().gety()
					+ "\nH1:\n\tH1x = " + this.getOpk().getH1().getx()
					+ "\n\tH1y = " + this.getOpk().getH1().gety()
					+ "\nH2:\n\tH2x = " + this.getOpk().getH2().getx()
					+ "\n\tH2y = " + this.getOpk().getH2().gety()
					+ "\n\nOsk:\ny1 = " + this.getOsk().gety1() + "\ny2 = "
					+ this.getOsk().gety2();
			long end = System.currentTimeMillis();
			System.out.println("Execution time was " + (end - start) + " ms.");
			System.out.println(print + "\n\n---------------DONE--------------");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public Opk getOpk() {
		return this.opk;
	}

	private Osk getOsk() {
		return this.osk;
	}

	// OPEN process
	@SuppressWarnings("unchecked")
	public String open(String message, Signature signature) {
		System.out.println("\n---------------Open protocol--------------\n");
		long start = System.currentTimeMillis();
		// Check if the signature is valid
		String result = "";
		try {
			// Check validity
			// Catch the fields
			EllipticCurve ec = new EllipticCurve(new secp256r1());
			ECPoint E0 = new ECPoint(ec, signature.getE0().getx(), signature
					.getE0().gety());
			ECPoint E1 = new ECPoint(ec, signature.getE1().getx(), signature
					.getE1().gety());
			ECPoint E2 = new ECPoint(ec, signature.getE2().getx(), signature
					.getE2().gety());
			// Compute S1 and S2
			ECPoint MinusY1E0 = new ECPoint(ec, E0.multiply(this.osk.gety1())
					.getx(), E0.multiply(this.osk.gety1()).gety().negate());
			ECPoint MinusY2E0 = new ECPoint(ec, E0.multiply(this.osk.gety2())
					.getx(), E0.multiply(this.osk.gety2()).gety().negate());
			ECPoint S1 = E1.add(MinusY1E0);
			ECPoint S2 = E2.add(MinusY2E0);
			System.out.println("S1:\n\tS1x = " + S1.getx() + "\n\tS1y = "
					+ S1.gety());
			System.out.println("S2:\n\tS2x = " + S2.getx() + "\n\tS2y = "
					+ S2.gety());
			if (S1.getx().equals(S2.getx()) && S1.gety().equals(S2.gety())) {
				System.out.println("Opening succesfull!!");
			} else {
				System.out.println("Opening failed...");
			}
			// Search pseudo user
			Boolean search = true;
			HashMap<String, Mpk> userList = this.issue.getMembersList();
			Iterator it = userList.keySet().iterator();
			while (it.hasNext() && search) {
				String pseudo = (String) it.next();
				Mpk mpk = userList.get(pseudo);
				if (mpk.geth().getx().compareTo(S1.getx()) == 0
						&& mpk.geth().gety().compareTo(S1.gety()) == 0) {
					System.out.println("\nPseudo of the user who signed: "
							+ pseudo);
					result = pseudo;
					search = false;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		System.out.println("\nExecution time was " + (end - start) + " ms.");
		System.out.println("\n---------------DONE--------------");
		return result;
	}

	public Boolean verify(String message, Signature signature) {
		Boolean valid = false;
		// Catch the fields
		try {
			int index = signature.getindex();
			int currentIndex = revoc.getCurrentIndex();
			Rpk rpk;
			if (index < currentIndex) {
				System.out.println("Index of Rpk:" + index);
				rpk = revoc.getCertificate(index + 1).getRpk();
			} else {
				rpk = revoc.getRpk();
			}
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
			// V0 OK
			ECPoint MinuscE0 = new ECPoint(ec, E0.multiply(c).getx(), E0
					.multiply(c).gety().negate());
			ECPoint tauEG = this.opk.getGenerator().multiply(tauE);
			ECPoint V0 = tauEG.add(MinuscE0);
			// V1 OK
			ECPoint MinuscE1 = new ECPoint(ec, E1.multiply(c).getx(), E1
					.multiply(c).gety().negate());
			ECPoint V1 = this.opk.getGenerator().multiply(taux)
					.add(this.opk.getH1().multiply(tauE)).add(MinuscE1);
			// V2 OK
			ECPoint MinuscE2 = new ECPoint(ec, E2.multiply(c).getx(), E2
					.multiply(c).gety().negate());
			ECPoint V2 = this.opk.getGenerator().multiply(taux)
					.add(this.opk.getH2().multiply(tauE)).add(MinuscE2);
			// Vmpk OK
			BigInteger a0a1 = (ipk.geta0().modPow(c, ipk.getn()).multiply(ipk
					.geta1().modPow(taux, ipk.getn()))).mod(ipk.getn());
			BigInteger a2A = (ipk.geta2().modPow(taus, ipk.getn())
					.multiply(ACOM.modPow(taue.negate(), ipk.getn()))).mod(ipk
					.getn());
			BigInteger Vmpk = (a0a1.multiply(a2A)).mod(ipk.getn());
			// Vrev OK
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
		return valid;
	}

}
