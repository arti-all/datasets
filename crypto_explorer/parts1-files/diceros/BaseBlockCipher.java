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

package com.intel.diceros.provider.symmetric.util;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.DataLengthException;
import com.intel.diceros.crypto.InvalidCipherTextException;
import com.intel.diceros.crypto.OutputLengthException;
import com.intel.diceros.crypto.modes.CBCBlockCipher;
import com.intel.diceros.crypto.modes.CTRBlockCipher;
import com.intel.diceros.crypto.modes.XTSBlockCipher;
import com.intel.diceros.crypto.params.CipherParameters;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.crypto.params.ParametersWithIV;
import com.intel.diceros.crypto.spec.SupportedSpecImpl;
import com.intel.diceros.crypto.spec.SupportedSpecSpi;
import com.intel.diceros.provider.DicerosProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Locale;

/**
 * Base Class for BlockCipher.
 */
public abstract class BaseBlockCipher extends CipherSpi {
  protected GenericBlockCipher cipher; // wrapping baseEngine, do some preprocessing work
  protected ParametersWithIV ivParam; // parameter of key data, initialization vector, etc
  protected int ivLength = -1; // the initialization vector length
  private SupportedSpecSpi supportedSpec;

  /**
   * Constructor
   *
   * @param engine the underlying cipher engine, do the actual encryption and
   *               decryption work
   */
  protected BaseBlockCipher(BlockCipher engine) {
    cipher = new GenericBlockCipherImpl(engine);
    supportedSpec = new SupportedSpecImpl();
  }

  /**
   * Constructor
   *
   * @param provider provide the the underlying cipher engine which does the actual
   *                 encryption and decryption work
   */
  protected BaseBlockCipher(BlockCipherProvider provider) {
    BlockCipher baseEngine = provider.get();

    int modeName = baseEngine.getMode();
    if (modeName == Constants.MODE_CTR) {
      cipher = new GenericBlockCipherImpl(new CTRBlockCipher(baseEngine));
    } else if (modeName == Constants.MODE_CBC) {
      cipher = new GenericBlockCipherImpl(new CBCBlockCipher(baseEngine));
    } else if (modeName == Constants.MODE_XTS) {
      cipher = new GenericBlockCipherImpl(new XTSBlockCipher(baseEngine));
    } else {
      cipher = new GenericBlockCipherImpl(baseEngine);
    }

    ivLength = baseEngine.getIVSize();
    supportedSpec = new SupportedSpecImpl();
  }

  @Override
  protected int engineGetBlockSize() {
    return cipher.getBlockSize();
  }

  @Override
  protected byte[] engineGetIV() {
    return (ivParam != null) ? ivParam.getIV() : null;
  }

  @Override
  protected int engineGetKeySize(Key key) {
    return key.getEncoded().length * 8;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    if (inputLen < 0) {
      throw new IllegalArgumentException("Input size must be equal "
              + "to or greater than zero");
    }
    return cipher.getOutputSize(inputLen);
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    AlgorithmParameters engineParams;
    String name = cipher.getUnderlyingCipher().getAlgorithmName();

    if (name.indexOf('/') >= 0) {
      name = name.substring(0, name.indexOf('/'));
    }

    try {
      engineParams = AlgorithmParameters.getInstance(name);
      engineParams.init(getAlgorithmParametersSpec());
    } catch (Exception e) {
      throw new RuntimeException(e.toString());
    }

    return engineParams;
  }

  protected AlgorithmParameterSpec getAlgorithmParametersSpec()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    byte[] iv = engineGetIV();
    if (iv == null) {
      if (cipher.getUnderlyingCipher().getMode() == Constants.MODE_GCM) {
        iv = new byte[Constants.GCM_DEFAULT_IV_LEN];
      } else {
        iv = new byte[cipher.getBlockSize()];
      }
      SecureRandom.getInstance("DRNG", "DC").nextBytes(iv);
    }
    return new IvParameterSpec(iv);
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    String modeName = mode.toUpperCase(Locale.ENGLISH);

    if (!modeName.startsWith("CTR")
        && !modeName.startsWith("CBC")
        && !modeName.startsWith("XTS")
        && !modeName.startsWith("GCM")) {
      throw new NoSuchAlgorithmException("can't support mode " + mode);
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    String paddingName = padding.toUpperCase(Locale.ENGLISH);

    if (paddingName.equals("NOPADDING") || paddingName.equals("PKCS5PADDING")) {
      cipher.setPadding(paddingName);
    } else {
      throw new NoSuchPaddingException("Padding " + padding + " unknown.");
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
      SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (!(key instanceof SecretKey)) {
      throw new InvalidKeyException("Key for algorithm " + key.getAlgorithm()
              + " not suitable for symmetric enryption.");
    }

    CipherParameters param = retrieveParam(opmode, key, params, random);
    try {
      switch (opmode) {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
          cipher.init(true, param);
          break;
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
          cipher.init(false, param);
          break;
        default:
          throw new InvalidParameterException("unknown opmode " + opmode
                  + " passed");
      }
    } catch (Exception e) {
      throw new InvalidKeyException(e.getMessage());
    }
  }

  protected ParametersWithIV retrieveParam(int opmode, Key key,
      AlgorithmParameterSpec params, SecureRandom random)
          throws InvalidKeyException, InvalidAlgorithmParameterException {
    ParametersWithIV param = retrieveParam(key, params);

    if (ivLength >= 0 && param.getIV() == null) {
      if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE)) {
        SecureRandom ivRandom = random;
        if (ivRandom == null) {
          try {
            ivRandom = SecureRandom.getInstance("DRNG",
                    DicerosProvider.PROVIDER_NAME);
          } catch (Exception e) {
            ivRandom = new SecureRandom();
          }
        }

        byte[] iv = null;
        if (ivLength == 0 &&
            cipher.getUnderlyingCipher().getMode() == Constants.MODE_GCM) {
          // default IV size for GCM mode is 96 bit.
          iv = new byte[Constants.GCM_DEFAULT_IV_LEN];
        } else if (ivLength > 0) {
          iv = new byte[ivLength];
        }
        ivRandom.nextBytes(iv);
        param.setIV(iv);
      } else {
        throw new InvalidAlgorithmParameterException(
                "no IV set when one expected");
      }
    }

    return param;
  }

  protected ParametersWithIV retrieveParam(Key key, AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    KeyParameter keyParam = new KeyParameter(key.getEncoded());
    byte[] iv = null;
    if (params == null) {
      iv = null;
    } else if (params instanceof IvParameterSpec) {
      if (ivLength > 0) {
        iv = ((IvParameterSpec)params).getIV();
        if (iv == null || iv.length != ivLength) {
          throw new InvalidAlgorithmParameterException("IV must be " + ivLength
                  + " bytes long.");
        }
      }
    } else {
      throw new InvalidAlgorithmParameterException("unknown parameter type.");
    }
    ParametersWithIV cipherParam = new ParametersWithIV(keyParam, iv);

    ivParam = cipherParam;

    return cipherParam;
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params,
      SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
    AlgorithmParameterSpec paramSpec = null;
    Class<? extends AlgorithmParameterSpec>[] availableSpecs =
        supportedSpec.getSupportedSpecs();
    if (params != null) {
      for (int i = 0; i != availableSpecs.length; i++) {
        try {
          paramSpec = params.getParameterSpec(availableSpecs[i]);
          break;
        } catch (Exception e) {
          // try another if possible
        }
      }
      if (paramSpec == null) {
        throw new InvalidAlgorithmParameterException("can't handle parameter "
            + params.toString());
      }
    }

    engineInit(opmode, key, paramSpec, random);
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e.getMessage());
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    int length = cipher.getOutputSize(inputLen);

    if (inputOffset < 0 || inputLen < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length is nagetive, or input exceeds the array boundary!");
    }

    if (length > 0) {
      byte[] out = new byte[length];
      int len = cipher.processBytes(input, inputOffset, inputLen, out, 0);
      if (len == 0) {
        return null;
      } else if (len != out.length) {
        byte[] tmp = new byte[len];
        System.arraycopy(out, 0, tmp, 0, len);
        return tmp;
      }
      return out;
    }

    cipher.processBytes(input, inputOffset, inputLen, null, 0);
    return null;
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
      byte[] output, int outputOffset) throws ShortBufferException {
    if (inputOffset < 0 || inputLen < 0 || outputOffset < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException("input offset or input length or output"
            + "offset is nagetive, or input exceeds the array boundary!");
    }

    try {
      return cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
    } catch (DataLengthException e) {
      throw new ShortBufferException(e.getMessage());
    }
  }

  @Override
  protected int engineUpdate(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException {
    if ((input == null) || (output == null)) {
      throw new IllegalArgumentException("Buffers must not be null");
    }
    if (input == output) {
      throw new IllegalArgumentException("Input and output buffers must "
              + "not be the same object, consider using buffer.duplicate()");
    }
    if (output.isReadOnly()) {
      throw new ReadOnlyBufferException();
    }
    return cipher.processByteBuffer(input, output);
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    if (inputOffset < 0 || inputLen < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length is nagetive, or input exceeds the array boundary!");
    }

    int len = 0;
    byte[] tmp = new byte[engineGetOutputSize(inputLen)];
    if (inputLen != 0) {
      len = cipher.processBytes(input, inputOffset, inputLen, tmp, 0);
    }
    try {
      len += cipher.doFinal(tmp, len);
    } catch (DataLengthException e) {
      throw new IllegalBlockSizeException(e.getMessage());
    } catch (InvalidCipherTextException e) {
      throw new BadPaddingException(e.getMessage());
    }
    if (len == tmp.length) {
      return tmp;
    }
    byte[] out = new byte[len];
    System.arraycopy(tmp, 0, out, 0, len);
    return out;
  }

  @Override
  protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
      byte[] output, int outputOffset) throws IllegalBlockSizeException,
      BadPaddingException, ShortBufferException {
    if (inputOffset < 0 || inputLen < 0 || outputOffset < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException("input offset or input length or output offset" +
          "is nagetive, or input exceeds the array boundary!");
    }

    try {
      int len = 0;
      if (inputLen != 0) {
        len = cipher.processBytes(input, inputOffset, inputLen, output,
                outputOffset);
      }
      return (len + cipher.doFinal(output, outputOffset + len));
    } catch (OutputLengthException e) {
      throw new ShortBufferException(e.getMessage());
    } catch (DataLengthException e) {
      throw new IllegalBlockSizeException(e.getMessage());
    } catch (InvalidCipherTextException e) {
      throw new BadPaddingException(e.getMessage());
    }
  }

  @Override
  protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    if ((input == null) || (output == null)) {
      throw new IllegalArgumentException("Buffers must not be null");
    }
    if (input == output) {
      throw new IllegalArgumentException("Input and output buffers must "
              + "not be the same object, consider using buffer.duplicate()");
    }
    if (output.isReadOnly()) {
      throw new ReadOnlyBufferException();
    }
    return cipher.doFinal(input, output);
  }

  static public interface GenericBlockCipher {
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException;

    public String getAlgorithmName();

    public BlockCipher getUnderlyingCipher();

    public int getOutputSize(int len);

    public int getBlockSize();

    public int processBytes(byte[] in, int inOff, int len, byte[] out,
        int outOff) throws DataLengthException;

    public int processByteBuffer(ByteBuffer input, ByteBuffer output)
        throws ShortBufferException;

    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException;

    public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException;

    public void setPadding(String padding) throws NoSuchPaddingException;

    public void updateAAD(byte[] src, int offset, int len);
    public void updateAAD(ByteBuffer src);

    public boolean isEncryption();
  }

  private static class GenericBlockCipherImpl implements GenericBlockCipher {
    private BlockCipher cipher;

    /**
     * the Padding type
     */
    private int padding = Constants.PADDING_NOPADDING;

    /**
     * are we encrypting or not?
     */
    private boolean forEncryption;

    /**
     * index of the content size left in the buffer
     */
    private int buffered = 0;

    /**
     * the head length of encryption
     */
    private int head = 0;

    /**
     * internal buffer
     */
    private int blockSize = 0;

    GenericBlockCipherImpl(BlockCipher cipher) {
      this.cipher = cipher;
      this.head = cipher.getHeadLength();
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException {
      this.buffered = 0;
      this.forEncryption = forEncryption;
      cipher.init(forEncryption, params);
      blockSize = cipher.getBlockSize();
    }

    @Override
    public String getAlgorithmName() {
      return cipher.getAlgorithmName();
    }

    @Override
    public BlockCipher getUnderlyingCipher() {
      return cipher;
    }

    @Override
    public int getOutputSize(int len) {
      if (len == 0 && head == 2) {
        return 0;
      }
      int totalLen = buffered + len;
      if (padding == Constants.PADDING_NOPADDING) {
        if (cipher.getMode() != Constants.MODE_GCM) {
          return totalLen;
        } else {
          if (forEncryption) {
            return cipher.getTagLen() + totalLen;
          } else {
            return totalLen - cipher.getTagLen();
          }
        }
      }
      if (!forEncryption)
        return totalLen;
      if (totalLen < blockSize)
        return blockSize;
      return totalLen + blockSize - (len % blockSize) + head;
    }

    @Override
    public int getBlockSize() {
      return cipher.getBlockSize();
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in     the input byte array.
     * @param inOff  the offset at which the input data starts.
     * @param len    the number of bytes to be copied out of the input array.
     * @param out    the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException   if there isn't enough space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out,
        int outOff) throws DataLengthException {
      if (len < 0) {
        throw new IllegalArgumentException(
                "Can't have a negative input length!");
      }
      int length = getOutputSize(len);
      if (length > 0) {
        if ((((forEncryption && padding == Constants.PADDING_NOPADDING) &&
                (outOff + length) > out.length) ||
                (!forEncryption && (outOff + length - blockSize) > out.length))) {
          throw new OutputLengthException("output buffer too short");
        }
      }

      int outConsumed = cipher.processBlock(in, inOff, len, out, outOff);
      if (cipher.getMode() == Constants.MODE_CBC) {
        buffered = buffered + len - outConsumed;
      }
      return outConsumed;
    }

    @Override
    public int processByteBuffer(ByteBuffer input, ByteBuffer output)
        throws ShortBufferException {
      return processByteBuffer(input, output, true);
    }

    @Override
    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException {
      try {
        int length = getOutputSize(0);
        if (outOff + length > out.length) {
          throw new OutputLengthException(
              "output buffer too short for doFinal()");
        }
        return cipher.doFinal(out, outOff);
      } catch (Exception e) {
        throw new RuntimeException(e);
      } finally {
        buffered = 0;
        reset();
      }
    }

    @Override
    public int doFinal(ByteBuffer input, ByteBuffer output)
        throws ShortBufferException {
      int result = 0;
      try {
        result = processByteBuffer(input, output, false);
      } catch (ShortBufferException e) {
        throw e;
      } finally {
        reset();
        buffered = 0;
      }
      return result;
    }

    private int processByteBuffer(ByteBuffer input, ByteBuffer output,
        boolean isUpdate) throws ShortBufferException {
      if ((input == null) || (output == null)) {
        throw new NullPointerException(
            "Input and output buffers must not be null");
      }
      int inPos = input.position();
      int inLimit = input.limit();
      int inLen = inLimit - inPos;
      if (isUpdate && inLen == 0) {
        return 0;
      }

      // input + data unprocessed = 0
      int outLenNeeded = getOutputSize(inLen);
      if (!isUpdate && outLenNeeded == 0) {
        return 0;
      }
      if (!input.isDirect() || !output.isDirect()) {
        throw new IllegalArgumentException(
            "ByteBuffer of input and output must be direct");
      }
      if (output.remaining() < outLenNeeded) {
        throw new ShortBufferException("Need at least " + outLenNeeded
            + " bytes of space in output buffer");
      }
      // need native process
      int n = cipher.processByteBuffer(input, output, isUpdate);
      if (cipher.getMode() == Constants.MODE_CBC) {
        buffered = buffered + inLen -n;
      }
      input.position(input.limit());
      output.position(output.position() + n);
      return n;
    }

    /**
     * Reset the buffer and cipher. After resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    public void reset() {
      cipher.reset();
    }

    public void setPadding(String paddingScheme) throws NoSuchPaddingException {
      if (paddingScheme == null) {
        throw new NoSuchPaddingException("null padding");
      } else if (paddingScheme.equalsIgnoreCase("NoPadding")) {
        padding = Constants.PADDING_NOPADDING;
      } else if (paddingScheme.equalsIgnoreCase("PKCS5Padding")) {
        padding = Constants.PADDING_PKCS5PADDING;
      } else {
        throw new NoSuchPaddingException("Padding: " + paddingScheme
            + " not implemented");
      }

      if ((padding != Constants.PADDING_NOPADDING)
          && (cipher.getMode() == Constants.MODE_CTR
              || cipher.getMode() == Constants.MODE_XTS
              || cipher.getMode() == Constants.MODE_GCM)) {
        throw new NoSuchPaddingException(cipher.getAlgorithmName() +
            " mode must be used with NoPadding");
      }

      cipher.setPadding(padding);
    }

    public void updateAAD(byte[] src, int offset, int len) {
      cipher.updateAAD(src, offset, len);
    }

    public void updateAAD(ByteBuffer src) {
      cipher.updateAAD(src);
    }

    public boolean isEncryption() {
      return this.forEncryption;
    }
  }
}
