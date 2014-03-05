/*
 * Copyright @ 2013-2014 yong.teng(webmaster@buession.com)
 * 
 * =================================================================================================
 * 
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 
 * (the "License"); you may not use this file except in compliance with the License. You may obtain 
 * a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 * 
 * =================================================================================================
 * 
 * This software consists of voluntary contributions made by many individuals on behalf of the
 * Apache Software Foundation. For more information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 * 
 * +------------------------------------------------------------------------------------------------+
 * | License: License: https://mcrypt.buession.com.cn/LICENSE 										|
 * | Author: Yong.Teng <webmaster@buession.com> 													|
 * +------------------------------------------------------------------------------------------------+
 */
package com.buession.mcrypt;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Mcrypt {

	private final static char[] HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f'};

	/**
	 * 请求算法的名称
	 */
	private String algo;

	/**
	 * 加密密钥
	 */
	private String salt;

	/**
	 * 字符串编码
	 */
	private String characterEncoding;

	/**
	 * 信息摘要对象的提供者
	 */
	private Provider provider = null;

	/**
	 * 重复加密次数
	 */
	private int count = 1;

	private final static Logger logger = LoggerFactory.getLogger(Mcrypt.class);

	public Mcrypt() {
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 */
	public Mcrypt(final String algo) {
		this.algo = algo;
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param count
	 *        重复加密次数
	 */
	public Mcrypt(final String algo, int count) {
		this(algo, null, count);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, int count, Provider provider) {
		this(algo, null, count, provider);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, Provider provider) {
		this.algo = algo;
		this.provider = provider;
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 */
	public Mcrypt(final String algo, final String characterEncoding) {
		this.algo = algo;
		this.characterEncoding = characterEncoding;
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, final String characterEncoding, Provider provider) {
		this.algo = algo;
		this.characterEncoding = characterEncoding;
		this.provider = provider;
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param count
	 *        重复加密次数
	 */
	public Mcrypt(final String algo, final String characterEncoding, int count) {
		this(algo, characterEncoding, null, count);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, final String characterEncoding, int count, Provider provider) {
		this(algo, characterEncoding, null, count, provider);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 */
	public Mcrypt(final String algo, final String characterEncoding, final String salt) {
		this(algo, characterEncoding, salt, null);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, final String characterEncoding, final String salt,
			Provider provider) {
		this.algo = algo;
		this.characterEncoding = characterEncoding;
		this.salt = salt;
		this.provider = provider;
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param count
	 *        重复加密次数
	 */
	public Mcrypt(final String algo, final String characterEncoding, final String salt, int count) {
		this(algo, characterEncoding, salt, count, null);
	}

	/**
	 * @param algo
	 *        请求算法的名称
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Mcrypt(final String algo, final String characterEncoding, final String salt, int count,
			Provider provider) {
		this(algo, characterEncoding, salt);

		if (count < 1) {
			throw new IllegalArgumentException("Count could not less than 1");
		}

		this.count = count;
		this.provider = provider;
	}

	/**
	 * 返回请求算法的名称
	 * 
	 * @return 返回请求算法的名称
	 */
	public String getAlgo() {
		return algo;
	}

	/**
	 * 设置请求算法的名称
	 * 
	 * @param algo
	 *        请求算法的名称
	 */
	public void setAlgo(String algo) {
		this.algo = algo;
	}

	/**
	 * 返回加密密钥
	 * 
	 * @return 加密密钥
	 */
	public String getSalt() {
		return salt;
	}

	/**
	 * 设置加密密钥
	 * 
	 * @param salt
	 *        加密密钥
	 */
	public void setSalt(String salt) {
		this.salt = salt;
	}

	/**
	 * 获取字符串编码
	 * 
	 * @return 字符串编码
	 */
	public String getCharacterEncoding() {
		return characterEncoding;
	}

	/**
	 * 设置字符串编码
	 * 
	 * @param characterEncoding
	 *        字符串编码
	 */
	public void setCharacterEncoding(String characterEncoding) {
		this.characterEncoding = characterEncoding;
	}

	/**
	 * 返回此信息摘要对象的提供者
	 * 
	 * @return 信息摘要对象的提供者
	 */
	public Provider getProvider() {
		return provider;
	}

	/**
	 * 设置信息摘要对象的提供者
	 * 
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public void setProvider(Provider provider) {
		this.provider = provider;
	}

	/**
	 * 返回重复加密次数
	 * 
	 * @return 重复加密次数
	 */
	public int getCount() {
		return count;
	}

	/**
	 * 设置重复加密次数
	 * 
	 * @param count
	 *        重复加密次数
	 */
	public void setCount(int count) {
		if (count < 1) {
			throw new IllegalArgumentException("Count could not less than 1");
		}

		this.count = count;
	}

	/**
	 * 字符串加密
	 * 
	 * @param str
	 *        需要加密的字符串
	 * @return 加密后的字符串
	 */
	public String encode(String str) {
		if (str == null) {
			throw new IllegalArgumentException("String could not be null");
		}

		if (algo == null || algo.length() == 0) {
			throw new RuntimeException("Algo could not be null");
		}

		try {
			MessageDigest messageDigest = provider == null ? MessageDigest.getInstance(algo)
					: MessageDigest.getInstance(algo, provider);

			return encode(str, messageDigest);
		} catch (final NoSuchAlgorithmException e) {
			throw new SecurityException(e);
		}
	}

	/**
	 * 字符串加密
	 * 
	 * @param str
	 *        需要加密的字符串
	 * @param messageDigest
	 *        实现指定摘要算法的 MessageDigest 对象
	 * @return 加密后的字符串
	 */
	private String encode(String str, MessageDigest messageDigest) {
		if (StringUtils.isEmpty(salt) == false) {
			str += salt;
		}

		try {
			if (StringUtils.isEmpty(this.characterEncoding)) {
				messageDigest.update(str.getBytes());
			} else {
				messageDigest.update(str.getBytes(this.characterEncoding));
			}

			final byte[] digest = messageDigest.digest();
			String result = getFormattedText(digest);

			logger.debug("Mcrypt encode string <{}> by algo <{}>, salt <{}>", algo, salt);
			while(--count > 0) {
				result = encode(result, messageDigest);
			}

			return result;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param bytes
	 * @return formatted string
	 */
	private static String getFormattedText(byte[] bytes) {
		final StringBuilder buffer = new StringBuilder(bytes.length * 2);

		for (int j = 0; j < bytes.length; j++) {
			buffer.append(HEX_DIGITS[(bytes[j] >> 4) & 0x0f]);
			buffer.append(HEX_DIGITS[bytes[j] & 0x0f]);
		}

		return buffer.toString();
	}

}