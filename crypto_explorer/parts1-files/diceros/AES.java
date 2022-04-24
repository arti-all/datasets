/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.intel.diceros.provider.symmetric;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.engines.AESMutliBufferEngine;
import com.intel.diceros.crypto.engines.AESOpensslEngine;
import com.intel.diceros.provider.symmetric.util.BaseBlockCipher;
import com.intel.diceros.provider.symmetric.util.BlockCipherProvider;
import com.intel.diceros.provider.symmetric.util.Constants;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class implements the AES algorithm in the mode <code>CTR</code>,
 * <code>CBC</code>, <code>XTS</code> and <code>MBCBC</code>.
 */
public class AES {
  private AES() {
  }

  public static final class CTR extends BaseBlockCipher {
    // Use the algorithm provided by default provider if Openssl is unavailable.
    private static boolean DCProviderAvailable =
        AESOpensslEngine.opensslEngineAvailable;
    private Cipher defaultCipher = null;

    /**
     * the constructor of CTR mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public CTR() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESOpensslEngine(Constants.MODE_CTR);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");
      }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
      if (DCProviderAvailable) {
        super.engineSetMode(mode);
      }
    }

    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
      if (DCProviderAvailable) {
        super.engineSetPadding(padding);
      }
    }

    @Override
    protected int engineGetBlockSize() {
      if (DCProviderAvailable) {
        return super.engineGetBlockSize();
      } else {
        return defaultCipher.getBlockSize();
      }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      if (DCProviderAvailable) {
        return super.engineGetOutputSize(inputLen);
      } else {
        return defaultCipher.getOutputSize(inputLen);
      }
    }

    @Override
    protected byte[] engineGetIV() {
      if (DCProviderAvailable) {
        return super.engineGetIV();
      } else {
        return defaultCipher.getIV();
      }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      if (DCProviderAvailable) {
        return super.engineGetParameters();
      } else {
        return defaultCipher.getParameters();
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, random);
      } else {
        defaultCipher.init(opmode, key, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen);
      }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen, output,
                outputOffset);
      }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal();
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen);
        }
      }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal(output, outputOffset);
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen, output,
                  outputOffset);
        }
      }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, output);
      } else {
        return defaultCipher.update(input, output);
      }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, output);
      } else {
        return defaultCipher.doFinal(input, output);
      }
    }
  }

  public static final class CBC extends BaseBlockCipher {
    // Use the algorithm provided by default provider if Openssl is unavailable.
    private static boolean DCProviderAvailable =
        AESOpensslEngine.opensslEngineAvailable;
    private Cipher defaultCipher = null;

    /**
     * the constructor of CBC mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public CBC() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESOpensslEngine(Constants.MODE_CBC);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      }
    }

    public CBC(BlockCipherProvider blockCipherProvider) {
      super(blockCipherProvider);
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
      if (DCProviderAvailable) {
        super.engineSetMode(mode);
      }
    }

    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
      if (DCProviderAvailable) {
        super.engineSetPadding(padding);
      } else {
        try {
          defaultCipher = Cipher.getInstance("AES/CBC/" + padding);
        } catch (NoSuchAlgorithmException e) {
          // ignore. If this mode is not supported, NoSuchAlgorithmException
          // will be thrown in the constructor.
        }
      }
    }

    @Override
    protected int engineGetBlockSize() {
      if (DCProviderAvailable) {
        return super.engineGetBlockSize();
      } else {
        return defaultCipher.getBlockSize();
      }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      if (DCProviderAvailable) {
        return super.engineGetOutputSize(inputLen);
      } else {
        return defaultCipher.getOutputSize(inputLen);
      }
    }

    @Override
    protected byte[] engineGetIV() {
      if (DCProviderAvailable) {
        return super.engineGetIV();
      } else {
        return defaultCipher.getIV();
      }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      if (DCProviderAvailable) {
        return super.engineGetParameters();
      } else {
        return defaultCipher.getParameters();
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, random);
      } else {
        defaultCipher.init(opmode, key, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen);
      }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen, output,
                outputOffset);
      }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal();
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen);
        }
      }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal(output, outputOffset);
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen, output,
                  outputOffset);
        }
      }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, output);
      } else {
        return defaultCipher.update(input, output);
      }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, output);
      } else {
        return defaultCipher.doFinal(input, output);
      }
    }
  }

  public static final class MBCBC extends BaseBlockCipher {
    // Use the algorithm provided by default provider if Openssl is unavailable.
    private static boolean DCProviderAvailable =
        AESMutliBufferEngine.opensslEngineAvailable;
    private Cipher defaultCipher = null;

    /**
     * the constructor of MBCBC mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public MBCBC() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESMutliBufferEngine(Constants.MODE_CBC);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
      if (DCProviderAvailable) {
        super.engineSetMode(mode);
      }
    }

    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
      if (DCProviderAvailable) {
        super.engineSetPadding(padding);
      }
    }

    @Override
    protected int engineGetBlockSize() {
      if (DCProviderAvailable) {
        return super.engineGetBlockSize();
      } else {
        return defaultCipher.getBlockSize();
      }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      if (DCProviderAvailable) {
        return super.engineGetOutputSize(inputLen);
      } else {
        return defaultCipher.getOutputSize(inputLen);
      }
    }

    @Override
    protected byte[] engineGetIV() {
      if (DCProviderAvailable) {
        return super.engineGetIV();
      } else {
        return defaultCipher.getIV();
      }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      if (DCProviderAvailable) {
        return super.engineGetParameters();
      } else {
        return defaultCipher.getParameters();
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, random);
      } else {
        defaultCipher.init(opmode, key, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      if (DCProviderAvailable) {
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
      } else {
        return defaultCipher.update(input, inputOffset, inputLen);
      }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
      if (DCProviderAvailable) {
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
      } else {
        return defaultCipher.update(input, inputOffset, inputLen, output,
                outputOffset);
      }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal();
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen);
        }
      }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal(output, outputOffset);
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen, output,
                  outputOffset);
        }
      }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      if (DCProviderAvailable) {
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
      } else {
        return defaultCipher.update(input, output);
      }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, output);
      } else {
        return defaultCipher.doFinal(input, output);
      }
    }
  }

  public static final class XTS extends BaseBlockCipher {
    // Use the algorithm provided by default provider if Openssl is unavailable.
    private static boolean DCProviderAvailable =
        AESOpensslEngine.opensslEngineAvailable;
    private Cipher defaultCipher = null;

    /**
     * the constructor of XTS mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public XTS() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESOpensslEngine(Constants.MODE_XTS);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/XTS/NoPadding", "SunJCE");
      }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
      if (DCProviderAvailable) {
        super.engineSetMode(mode);
      }
    }

    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
      if (DCProviderAvailable) {
        super.engineSetPadding(padding);
      } else {
        if (!padding.equalsIgnoreCase("NoPadding")) {
          try {
            defaultCipher = Cipher.getInstance("AES/XTS/" + padding);
          } catch (NoSuchAlgorithmException e) {
            // ignore. If this mode is not supported, NoSuchAlgorithmException
            // will be thrown in the constructor.
          }
        }
      }
    }

    @Override
    protected int engineGetBlockSize() {
      if (DCProviderAvailable) {
        return super.engineGetBlockSize();
      } else {
        return defaultCipher.getBlockSize();
      }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      if (DCProviderAvailable) {
        return super.engineGetOutputSize(inputLen);
      } else {
        return defaultCipher.getOutputSize(inputLen);
      }
    }

    @Override
    protected byte[] engineGetIV() {
      if (DCProviderAvailable) {
        return super.engineGetIV();
      } else {
        return defaultCipher.getIV();
      }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      if (DCProviderAvailable) {
        return super.engineGetParameters();
      } else {
        return defaultCipher.getParameters();
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, random);
      } else {
        defaultCipher.init(opmode, key, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
      if (DCProviderAvailable) {
        super.engineInit(opmode, key, params, random);
      } else {
        defaultCipher.init(opmode, key, params, random);
      }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen);
      }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        return defaultCipher.update(input, inputOffset, inputLen, output,
                outputOffset);
      }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal();
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen);
        }
      }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, inputOffset, inputLen, output,
                outputOffset);
      } else {
        if (input == null && inputOffset == 0 && inputLen == 0) {
          return defaultCipher.doFinal(output, outputOffset);
        } else {
          return defaultCipher.doFinal(input, inputOffset, inputLen, output,
                  outputOffset);
        }
      }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      if (DCProviderAvailable) {
        return super.engineUpdate(input, output);
      } else {
        return defaultCipher.update(input, output);
      }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
      if (DCProviderAvailable) {
        return super.engineDoFinal(input, output);
      } else {
        return defaultCipher.doFinal(input, output);
      }
    }
  }
}
