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
import java.util.Random;

import groupsignature.elliptic.ECPoint;
import groupsignature.elliptic.EllipticCurve;
import groupsignature.elliptic.secp256r1;
import groupsignature.keys.*;
import groupsignature.server.*;
import groupsignature.signature.RevocationCertificate;
import groupsignature.signature.Signature;
import groupsignature.utils.*;

public class User {

	private IssuingManager issue;
	private OpeningManager open;
	private RevocationManager revoc;
	private Msk msk;
	private Mpk mpk;
	private Ipk ipk;
	private Rpk rpk;
	private Integer index;
	private Opk opk;
	private String pseudo;

	/*
	 * Class constructor
	 */
	public User(String pseudo, IssuingManager issue, OpeningManager open,
			RevocationManager revoc) {
		this.pseudo = pseudo;
		this.issue = issue;
		this.open = open;
		this.revoc = revoc;
		this.ipk = this.issue.getIpk();
		this.rpk = this.revoc.getRpk();
		this.opk = this.open.getOpk();
		this.index = this.revoc.getCurrentIndex();
	}

	private Msk getMsk() {
		return this.msk;
	}

	public Mpk getMpk() {
		return this.mpk;
	}

	public IssuingManager getIssuingmanager() {
		return this.issue;
	}

	private OpeningManager getOpeningManager() {
		return this.open;
	}

	public String getPseudo() {
		return this.pseudo;
	}

	/**
	 * Join the group
	 * 
	 */
	public void join() {
		System.out.println("\n---------------Join protocol--------------");
		long start = System.currentTimeMillis();
		try {
			// Randomly choose xPrime
			BigInteger xPrime = new BigInteger(Constants.lam - 1, new Random());
			System.out.println("U: x' = " + xPrime);
			// Ask IssuingManager for xSecond
			BigInteger xSecond = this.getIssuingmanager().getJoinXSecond();
			// Compute x = (x'+x") mod (2^lam)
			BigInteger x = xPrime.add(xSecond).mod(Constants.expLam);
			System.out.println("U: x = " + x);
			// Compute A'
			BigInteger APrime = ipk.geta1().modPow(x, ipk.getn());
			System.out.println("U: A' = " + APrime);
			// Compute h
			EllipticCurve ec = new EllipticCurve(new secp256r1());
			ECPoint h = this.opk.getGenerator().multiply(x);
			if (ec.onCurve(h)) {
				System.out.println("U:h is on mother curve");
			}
			System.out.println("U: h:\n\thx = " + h.getx() + "\n\thy = "
					+ h.gety());
			// Get certificate
			Mpk certificat = this.getIssuingmanager().getCertificate(
					this.getPseudo(), APrime, h);
			// Check that a0a1^x = A^e mod n
			// Compute e
			BigInteger e = certificat.getEPrime().add(Constants.expKe);
			BigInteger link = (ipk.geta1().modPow(x, ipk.getn())).multiply(
					ipk.geta0()).mod(ipk.getn());
			BigInteger right = certificat.getA().modPow(e, ipk.getn());
			if (link.equals(right)) {
				System.out.println("U: Certificate checked succesfully!\n");
				this.mpk = certificat;
				this.msk = new Msk(x);
				System.out.println("\nMpk:\nA = " + this.getMpk().getA()
						+ "\ne' = " + this.getMpk().getEPrime() + "\nB = "
						+ this.getMpk().getB() + "\nh:\n\thx = "
						+ this.getMpk().geth().getx() + "\n\thy = "
						+ this.getMpk().geth().gety() + "\n\nMsk:\nx = "
						+ this.getMsk().getx());
			} else {
				System.out.println("U: Certificate corrupted...\n");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		System.out.println("\nExecution time was " + (end - start) + " ms.");
		System.out.println("\n---------------DONE--------------");
	}

	/**
	 * Update Key
	 * 
	 */
	public void updateKey() {
		System.out
				.println("\n---------------Update Key protocol--------------");
		long start = System.currentTimeMillis();
		// Get revocation certificate
		int currentIndex = this.revoc.getCurrentIndex();
		if (this.index < currentIndex) {
			Integer i;
			System.out.println("Number of updates: "
					+ Integer.toString(currentIndex - index));
			for (i = index + 1; i <= currentIndex; i++) {
				RevocationCertificate certif = revoc.getCertificate(i);
				Mpk revocMpk = certif.getMpk();
				if (this.mpk.getA().compareTo(revocMpk.getA()) == 0
						&& mpk.getB().compareTo(revocMpk.getB()) == 0
						&& mpk.getEPrime().compareTo(revocMpk.getEPrime()) == 0
						&& mpk.geth().getx().compareTo(revocMpk.geth().getx()) == 0
						&& mpk.geth().gety().compareTo(revocMpk.geth().gety()) == 0) {
					System.out.println("I was revoked...");
				} else {
					BigInteger B = this.revoc
							.getNewCertificat(this.mpk, certif);
					this.mpk.setB(B);
					System.out.println("B new = " + this.mpk.getB());
				}
			}
			this.index = currentIndex;
			this.rpk = this.revoc.getRpk();
		} else {
			System.out.println("Number of update: 0");
		}
		long end = System.currentTimeMillis();
		System.out.println("\nExecution time was " + (end - start) + " ms.");
		System.out.println("\n---------------DONE--------------");
	}

	/**
	 * Sign the signature
	 * 
	 * @param message
	 * 
	 */
	public Signature sign(String message) {
		System.out.println("\n---------------Sign protocol--------------");
		this.updateKey();
		this.rpk = revoc.getRpk();
		System.out.println("\nUser: " + this.pseudo + "\n\nMessage to sign: "
				+ message);
		long start = System.currentTimeMillis();
		Signature signature = null;
		try {
			EllipticCurve ec = new EllipticCurve(new secp256r1());
			Utils utils = new Utils();
			// Choose randomly RoE
			BigInteger roE = new BigInteger(opk.getOrder().bitLength() - 1,
					new Random());
			// Compute E
			ECPoint E0 = opk.getGenerator().multiply(roE);
			ECPoint E1 = mpk.geth().add(opk.getH1().multiply(roE));
			ECPoint E2 = mpk.geth().add(opk.getH2().multiply(roE));
			if (!ec.onCurve(E0) || !ec.onCurve(E1) || !ec.onCurve(E2)) {
				System.out
						.println("Problem with points E: not on mother curve!!");
			}
			// Compute ACOM and s
			BigInteger roM = utils.getRandomBinaryString(Constants.Kn / 2);
			BigInteger ACOM = (mpk.getA().multiply(ipk.geta2().modPow(roM,
					ipk.getn()))).mod(ipk.getn());
			BigInteger s = (mpk.getEPrime().add(Constants.expKe)).multiply(roM);
			// Compute BCOM and l
			BigInteger roR = utils.getRandomBinaryString(Constants.Kl / 2);
			BigInteger BCOM = (mpk.getB().multiply(rpk.getw().modPow(roR,
					rpk.getl()))).mod(rpk.getl());
			BigInteger t = mpk.getEPrime().multiply(roR);
			// Choose randomly mu's
			BigInteger mux = utils.getRandomBinaryString(Constants.lam
					+ Constants.Ks + Constants.Kc);
			BigInteger mus = utils.getRandomBinaryString(Constants.Kn / 2
					+ Constants.Ks + Constants.Kc);
			BigInteger mueprime = utils.getRandomBinaryString(Constants.KePrime
					+ Constants.Ks + Constants.Kc);
			BigInteger mut = utils.getRandomBinaryString(Constants.Kl / 2
					+ Constants.Ks + Constants.Kc);
			BigInteger muE = new BigInteger(opk.getOrder().bitLength() - 1,
					new Random());
			// Compute VcomCipher
			ECPoint V0 = opk.getGenerator().multiply(muE);
			ECPoint V1 = (opk.getGenerator().multiply(mux)).add(opk.getH1()
					.multiply(muE));
			ECPoint V2 = (opk.getGenerator().multiply(mux)).add(opk.getH2()
					.multiply(muE));
			if (!ec.onCurve(V0) || !ec.onCurve(V1) || !ec.onCurve(V2)) {
				System.out
						.println("Problem with points V: not on mother curve!!");
			}
			// Compute Vmpk
			BigInteger Vmpk = (((ipk.geta1().modPow(mux, ipk.getn())
					.multiply(ipk.geta2().modPow(mus, ipk.getn()))).mod(ipk
					.getn())).multiply(ACOM.modPow(mueprime.negate(),
					ipk.getn())).mod(ipk.getn()));
			// Compute Vrev
			BigInteger Vrev = ((rpk.getw().modPow(mut, rpk.getl()))
					.multiply(BCOM.modPow(mueprime.negate(), rpk.getl())))
					.mod(this.rpk.getl());
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
			BigInteger c = new BigInteger(1, md.digest());
			// Compute tau's
			BigInteger taux = c.multiply(this.msk.getx()).add(mux);
			BigInteger taus = c.multiply(s).add(mus);
			BigInteger taut = c.multiply(t).add(mut);
			BigInteger tauePrime = c.multiply(this.mpk.getEPrime()).add(
					mueprime);
			BigInteger tauE = (c.multiply(roE).add(muE)).mod(this
					.getOpeningManager().getOpk().getOrder());
			// Signature formating
			signature = new Signature(E0, E1, E2, ACOM, BCOM, c, taux, taus,
					tauePrime, taut, tauE, this.index);
			System.out.println("\nSignature:\nE = { E0, E1, E2 }\nACOM = "
					+ ACOM + "\nBCOM = " + BCOM + "\nc = " + c + "\nTx = "
					+ taux + "\nTs = " + taus + "\nTe' = " + tauePrime
					+ "\nTt = " + taut + "\nTE = " + tauE + "\nIndex = "
					+ this.index);
		} catch (Exception e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		System.out.println("\nExecution time was " + (end - start) + " ms.");
		System.out.println("\n---------------DONE--------------");
		return signature;
	}

}
