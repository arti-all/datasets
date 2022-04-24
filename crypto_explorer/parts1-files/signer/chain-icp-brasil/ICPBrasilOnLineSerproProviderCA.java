/*
 * Demoiselle Framework
 * Copyright (C) 2017 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "License.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package org.demoiselle.signer.chain.icp.brasil.provider.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.bind.DatatypeConverter;

import org.demoiselle.signer.chain.icp.brasil.provider.ChainICPBrasilConfig;
import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.util.Downloads;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * Get/Download the ICP-BRASIL's Trusted Certificate Authority Chain from 
 * SERPRO's mirror URL http://repositorio.serpro.gov.br/icp-brasil/ACcompactado.zip
*/

public class ICPBrasilOnLineSerproProviderCA implements ProviderCA {

	private static final String STRING_URL_ZIP = ChainICPBrasilConfig.getInstance().getUrl_local_ac_list();
	private static final String STRING_URL_HASH = ChainICPBrasilConfig.getInstance().getUrl_local_ac_list_sha512();

	private static final Logger LOGGER = Logger.getLogger(ICPBrasilOnLineSerproProviderCA.class.getName());
	
	
	protected static MessagesBundle chainMessagesBundle = new MessagesBundle();

	/**
	 *  return the address (mirrored by SERPRO) where is located a compacted file that contains the chain of ICP-BRASIL's trusted Certificate Authority.
	 * @return address (mirrored by SERPRO) where is located a compacted file that contains the chain of ICP-BRASIL's trusted Certificate Authority.
	 */
	public String getURLZIP() {
		return ICPBrasilOnLineSerproProviderCA.STRING_URL_ZIP;
	}

	/**
	 *  return the address (mirrored by SERPRO) where is located a file that contains the hash code (SHA512)
	 *  which corresponds to the file downloaded with {@link #getURLZIP()} . 
	 * @return address (mirrored by SERPRO) where is located a file that contains the hash code (SHA512)
	 *  which corresponds to the file downloaded with {@link #getURLZIP()} . 
	 */
	public String getURLHash() {
		return ICPBrasilOnLineSerproProviderCA.STRING_URL_HASH;
	}

	/** 
	 * Read Certificate Authority chain from file 
	 */
	@Override
	public Collection<X509Certificate> getCAs() {

		Collection<X509Certificate> result = null;
		boolean useCache = false;

		try {

			// Faz o hash do checksum do arquivo, e não usa o arquivo local de propósito,
			// pois o arquivo pode ter sido corrompido e neste caso o check vai
			// dar errado e baixar novamente
			Path pathZip = ICPBrasilUserHomeProviderCA.FULL_PATH_ZIP;
			if (Files.exists(pathZip)) {

				// Baixa o hash do endereço online
				InputStream inputStreamHash = Downloads.getInputStreamFromURL(getURLHash());

				// Convert o input stream em string
				Scanner scannerOnlineHash = new Scanner(inputStreamHash);
				scannerOnlineHash.useDelimiter("\\A");
				String onlineHash = scannerOnlineHash.hasNext() ? scannerOnlineHash.next() : "";
				scannerOnlineHash.close();

				if (!onlineHash.equals("")) {

					// Gera o hash do arquivo local
					String localZipHash = DatatypeConverter.printHexBinary(checksum(new File(pathZip.toString())));
					
					// Pega SOMENTE o hash sem o nome do arquivo
					String onlineHashWithouFilename = onlineHash.replace(ICPBrasilUserHomeProviderCA.FILENAME_ZIP, "")
							.replaceAll(" ", "").replaceAll("\n", "");

					if (onlineHashWithouFilename.equalsIgnoreCase(localZipHash)) {
						useCache = true;
					} else {
						useCache = false;
					}

				} else {
					LOGGER.log(Level.WARNING, chainMessagesBundle.getString("error.hash.empty"));
				}
			}

			// Se não é para pegar do cache os certificados ele baixa o novo e
			// salva localmente
			if (!useCache) {
				// Baixa um novo arquivo
				LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.file.downloading",getURLZIP() ));
				InputStream inputStreamZip = Downloads.getInputStreamFromURL(getURLZIP());
				Files.copy(inputStreamZip, pathZip, StandardCopyOption.REPLACE_EXISTING);
				inputStreamZip.close();

				LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.sucess"));	
			}
			
			// Pega os certificados locais
			InputStream inputStreamZipReturn = new FileInputStream(pathZip.toString());
			result = getFromZip(inputStreamZipReturn);
			inputStreamZipReturn.close();

			LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.recovered.certs",result.size()));

		} catch (IOException e) {			
			LOGGER.log(Level.WARNING,chainMessagesBundle.getString("error.recover.file") , e.getMessage());			
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE, chainMessagesBundle.getString("error.exception.recorver.chain"), e.getMessage());
		}

		if (result != null) {
			LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.number.certificates.found",getName(), result.size()));
		} else {
			LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.none.certificates",getName()));
		}

		return result;
	}

	/**
	 * calculte SHA-512 hash from downloaded file.  
	 * @param input file to read from
	 * @return byte array with calculated hash
	 * @throws IOException Exception
	 */
	public byte[] checksum(File input) throws IOException {
		InputStream in = null;
		try {
			in = new FileInputStream(input);

			MessageDigest digest = MessageDigest.getInstance("SHA-512");
			byte[] block = new byte[4096];
			int length;
			while ((length = in.read(block)) > 0) {
				digest.update(block, 0, length);
			}
			return digest.digest();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (in != null)
				in.close();

		}
		return null;
	}

	/**
	 * Get from SERPRO mirror repository
	 * @param zip Input stream to read from
	 * @return Collection&lt;X509Certificate&gt;
	 */
	public Collection<X509Certificate> getOnline(InputStream zip) {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		long timeBefore = 0;
		long timeAfter = 0;
		try {
			timeBefore = System.currentTimeMillis();
			result = this.getFromZip(zip);
			timeAfter = System.currentTimeMillis();
		} catch (Throwable error) {
			timeAfter = System.currentTimeMillis();
			LOGGER.log(Level.SEVERE, chainMessagesBundle.getString("error.throwable", error.getMessage()));
		} finally {
			LOGGER.log(Level.INFO, chainMessagesBundle.getString("info.time.total", (timeAfter - timeBefore)));  
		}

		return result;
	}

	/**
	 *  get Chain from file stored on local user diretory 
	 * @param zip input stream to read from
	 * @return Collection&lt;X509Certificate&gt;
	 * @throws RuntimeException exception
	 */
	public Collection<X509Certificate> getFromZip(InputStream zip) throws RuntimeException {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		InputStream in = new BufferedInputStream(zip);
		ZipInputStream zin = new ZipInputStream(in);
		ZipEntry localFile = null;
		try {
			while ((localFile = zin.getNextEntry()) != null) {
				if (!localFile.isDirectory()) {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					byte[] b = new byte[512];
					int len = 0;
					while ((len = zin.read(b)) != -1)
						out.write(b, 0, len);
					ByteArrayInputStream is = new ByteArrayInputStream(out.toByteArray());
					out.close();
					X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509")
							.generateCertificate(is);
					is.close();
					result.add(certificate);
				}
			}
		} catch (CertificateException error) {
			throw new RuntimeException(chainMessagesBundle.getString("error.invalid.certificate"), error);
		} catch (IOException error) {
			throw new RuntimeException(chainMessagesBundle.getString("error.stream"), error);
		}
		return result;
	}

	
	/**
	 * This provider Name
	 */
	@Override
	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.serpro", getURLZIP());
	}

}