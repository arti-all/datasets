/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Vimil.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cwctravel.plugins.jenkins.trustcredentials;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.CheckForNull;
import javax.annotation.concurrent.GuardedBy;
import javax.servlet.ServletException;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.CertificateCredentials;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.trilead.ssh2.crypto.Base64;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;

public class TrustCredentialsImpl extends BaseStandardCredentials
		implements StandardCredentials, CertificateCredentials {

	private static final long serialVersionUID = -1665992101461745455L;

	private static final Logger LOGGER = Logger.getLogger(TrustCredentialsImpl.class.getName());

	/**
	 * The source of the keystore.
	 */
	private final TrustStoreSource trustStoreSource;

	/**
	 * The password.
	 */
	private final Secret password;

	/**
	 * The keystore.
	 */
	@GuardedBy("this")
	@CheckForNull
	private transient KeyStore trustStore;

	@GuardedBy("this")
	private transient long trustStoreLastModified;

	@DataBoundConstructor
	public TrustCredentialsImpl(CredentialsScope scope, String id, String description, @CheckForNull String password,
			@NonNull TrustStoreSource trustStoreSource) {
		super(scope, id, description);
		trustStoreSource.getClass();
		this.password = Secret.fromString(password);
		this.trustStoreSource = trustStoreSource;

		TrustCredentialsUtil.reloadTrustStores(this);

	}

	@Override
	public KeyStore getKeyStore() {
		return getTrustStore();
	}

	public KeyStore getTrustStore() {
		long lastModified = trustStoreSource.getTrustStoreLastModified();
		if (trustStore == null || trustStoreLastModified < lastModified) {
			KeyStore keyStore;
			try {
				keyStore = KeyStore.getInstance("JKS");
			} catch (KeyStoreException e) {
				throw new IllegalStateException("JKS is a trustStore type per the JLS spec", e);
			}
			try {
				keyStore.load(new ByteArrayInputStream(trustStoreSource.getTrustStoreBytes()), toCharArray(password));
			} catch (CertificateException e) {
				LOGGER.log(Level.WARNING, "Could not load trustStore from " + trustStoreSource.toString(), e);
			} catch (NoSuchAlgorithmException e) {
				LOGGER.log(Level.WARNING, "Could not load trustStore from " + trustStoreSource.toString(), e);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Could not load trustStore from " + trustStoreSource.toString(), e);
			}
			this.trustStore = keyStore;
			this.trustStoreLastModified = lastModified;
		}
		return trustStore;
	}

	@NonNull
	public Secret getPassword() {
		return password;
	}

	public boolean isPasswordEmpty() {
		return StringUtils.isEmpty(password.getPlainText());
	}

	public TrustStoreSource getTrustStoreSource() {
		return trustStoreSource;
	}

	private static char[] toCharArray(Secret password) {
		String plainText = Util.fixEmpty(password.getPlainText());
		return plainText == null ? null : plainText.toCharArray();
	}

	@Extension(ordinal = -1)
	public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

		@Override
		public String getDisplayName() {
			return Messages.TrustCredentialsImpl_DisplayName();
		}

		public DescriptorExtensionList<TrustStoreSource, Descriptor<TrustStoreSource>> getTrustStoreSources() {
			// TODO switch to Jenkins.getActiveInstance() once 1.590+ is the
			// baseline
			Jenkins jenkins = Jenkins.getInstance();
			if (jenkins == null) {
				throw new IllegalStateException("Jenkins has not been started, or was already shut down");
			}
			return jenkins.getDescriptorList(TrustStoreSource.class);
		}

	}

	public static abstract class TrustStoreSource extends AbstractDescribableImpl<TrustStoreSource> {

		@NonNull
		public abstract byte[] getTrustStoreBytes();

		public abstract long getTrustStoreLastModified();

		/**
		 * Returns {@code true} if and only if the source is self contained.
		 *
		 * @return {@code true} if and only if the source is self contained.
		 * @since 1.14
		 */
		public boolean isSnapshotSource() {
			return false;
		}

	}

	public static abstract class TrustStoreSourceDescriptor extends Descriptor<TrustStoreSource> {
		protected TrustStoreSourceDescriptor() {
			super();
		}

		protected TrustStoreSourceDescriptor(Class<? extends TrustStoreSource> clazz) {
			super(clazz);
		}

		protected static FormValidation validateCertificateKeystore(String type, byte[] trustStoreBytes,
				String password) {

			char[] passwordChars = toCharArray(Secret.fromString(password));
			try {
				KeyStore keyStore = KeyStore.getInstance(type);
				keyStore.load(new ByteArrayInputStream(trustStoreBytes), passwordChars);
				int size = keyStore.size();
				if (size == 0) {
					return FormValidation.warning(Messages.TrustCredentialsImpl_EmptyTrustStore());
				}
				StringBuilder buf = new StringBuilder();
				boolean first = true;
				for (Enumeration<String> enumeration = keyStore.aliases(); enumeration.hasMoreElements();) {
					String alias = enumeration.nextElement();
					if (first) {
						first = false;
					} else {
						buf.append(", ");
					}
					buf.append(alias);
					if (keyStore.isCertificateEntry(alias)) {
						keyStore.getCertificate(alias);
					} else if (keyStore.isKeyEntry(alias)) {
						if (passwordChars == null) {
							return FormValidation.warning(
									Messages.TrustCredentialsImpl_LoadCertificateFailedQueryEmptyPassword(alias));
						}
						try {
							keyStore.getKey(alias, passwordChars);
						} catch (UnrecoverableEntryException e) {
							return FormValidation.warning(e,
									Messages.TrustCredentialsImpl_LoadCertificateFailed(alias));
						}
					}
				}
				return FormValidation.ok(StringUtils.defaultIfEmpty(
						StandardCertificateCredentials.NameProvider.getSubjectDN(keyStore), buf.toString()));
			} catch (KeyStoreException e) {
				return FormValidation.warning(e, Messages.TrustCredentialsImpl_LoadTrustStoreFailed());
			} catch (CertificateException e) {
				return FormValidation.warning(e, Messages.TrustCredentialsImpl_LoadTrustStoreFailed());
			} catch (NoSuchAlgorithmException e) {
				return FormValidation.warning(e, Messages.TrustCredentialsImpl_LoadTrustStoreFailed());
			} catch (IOException e) {
				return FormValidation.warning(e, Messages.TrustCredentialsImpl_LoadTrustStoreFailed());
			} finally {
				if (passwordChars != null) {
					Arrays.fill(passwordChars, ' ');
				}
			}
		}
	}

	/**
	 * Let the user reference a file on the disk.
	 */
	public static class FileOnMasterTrustStoreSource extends TrustStoreSource {

		/**
		 * Our logger.
		 */
		private static final Logger LOGGER = Logger.getLogger(FileOnMasterTrustStoreSource.class.getName());

		/**
		 * The path of the file on the master.
		 */
		private final String trustStoreFile;

		@DataBoundConstructor
		public FileOnMasterTrustStoreSource(String trustStoreFile) {
			this.trustStoreFile = trustStoreFile;
		}

		/**
		 * {@inheritDoc}
		 */
		@NonNull
		@Override
		public byte[] getTrustStoreBytes() {
			try {
				InputStream inputStream = new FileInputStream(new File(trustStoreFile));
				try {
					return IOUtils.toByteArray(inputStream);
				} finally {
					IOUtils.closeQuietly(inputStream);
				}
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Could not read private store file " + trustStoreFile, e);
				return new byte[0];
			}
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public long getTrustStoreLastModified() {
			return new File(trustStoreFile).lastModified();
		}

		/**
		 * Returns the private key file name.
		 *
		 * @return the private key file name.
		 */
		public String getTrustStoreFile() {
			return trustStoreFile;
		}

		/**
		 * {@inheritDoc}
		 */
		@Extension
		public static class DescriptorImpl extends TrustStoreSourceDescriptor {

			/**
			 * {@inheritDoc}
			 */
			@Override
			public String getDisplayName() {
				return Messages.TrustCredentialsImpl_FileOnMasterTrustStoreSourceDisplayName();
			}

			public FormValidation doCheckKeyStoreFile(@QueryParameter String value, @QueryParameter String password) {
				if (StringUtils.isBlank(value)) {
					return FormValidation.error(Messages.TrustCredentialsImpl_TrustStoreFileUnspecified());
				}
				File file = new File(value);
				if (file.isFile()) {
					try {
						return validateCertificateKeystore("JKS", FileUtils.readFileToByteArray(file), password);
					} catch (IOException e) {
						return FormValidation.error(Messages.TrustCredentialsImpl_TrustStoreFileUnreadable(value), e);
					}
				} else {
					return FormValidation.error(Messages.TrustCredentialsImpl_TrustStoreFileDoesNotExist(value));
				}
			}

		}
	}

	/**
	 * Let the user reference a file on the disk.
	 */
	public static class UploadedTrustStoreSource extends TrustStoreSource implements Serializable {
		/**
		 * Ensure consistent serialization.
		 */
		private static final long serialVersionUID = 1L;

		/**
		 * Our logger.
		 */
		private static final Logger LOGGER = Logger.getLogger(UploadedTrustStoreSource.class.getName());

		/**
		 * The uploaded keystore.
		 */
		@CheckForNull
		private final Secret uploadedKeystore;

		@DataBoundConstructor
		public UploadedTrustStoreSource(String uploadedTruststore) {
			this.uploadedKeystore = StringUtils.isBlank(uploadedTruststore) ? null
					: Secret.fromString(uploadedTruststore);
		}

		/**
		 * {@inheritDoc}
		 */
		@NonNull
		@Override
		public byte[] getTrustStoreBytes() {
			return DescriptorImpl.toByteArray(uploadedKeystore);
		}

		@Override
		public long getTrustStoreLastModified() {
			return 0L;
		}

		/**
		 * Returns the private key file name.
		 *
		 * @return the private key file name.
		 */
		public String getUploadedTruststore() {
			return uploadedKeystore == null ? "" : uploadedKeystore.getEncryptedValue();
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public boolean isSnapshotSource() {
			return true;
		}

		/**
		 * {@inheritDoc}
		 */
		@Extension
		public static class DescriptorImpl extends TrustStoreSourceDescriptor {

			/**
			 * {@inheritDoc}
			 */
			@Override
			public String getDisplayName() {
				return Messages.TrustCredentialsImpl_UploadedTrustStoreSourceDisplayName();
			}

			public static byte[] toByteArray(Secret secret) {
				if (secret != null) {
					try {
						return Base64.decode(secret.getPlainText().toCharArray());
					} catch (IOException e) {
						// ignore
					}
				}
				return new byte[0];
			}

			public static Secret toSecret(byte[] contents) {
				return contents == null || contents.length == 0 ? null
						: Secret.fromString(new String(Base64.encode(contents)));
			}

			public FormValidation doCheckUploadedKeystore(@QueryParameter String value,
					@QueryParameter String password) {
				if (StringUtils.isBlank(value)) {
					return FormValidation.error(Messages.TrustCredentialsImpl_NoCertificateUploaded());
				}
				return validateCertificateKeystore("JKS", toByteArray(Secret.fromString(value)), password);
			}

			public Upload getUpload(String divId) {
				return new Upload(divId, null);
			}

		}

		public static class Upload {

			private final String divId;

			private final Secret uploadedTruststore;

			public Upload(String divId, Secret uploadedTruststore) {
				this.divId = divId;
				this.uploadedTruststore = uploadedTruststore;
			}

			public String getDivId() {
				return divId;
			}

			public Secret getUploadedTruststore() {
				return uploadedTruststore;
			}

			public HttpResponse doUpload(StaplerRequest req) throws ServletException, IOException {
				FileItem file = req.getFileItem("truststore.file");
				if (file == null) {
					throw new ServletException("no file upload");
				}
				return HttpResponses.forwardToView(
						new Upload(getDivId(), UploadedTrustStoreSource.DescriptorImpl.toSecret(file.get())),
						"complete");
			}
		}
	}

}
