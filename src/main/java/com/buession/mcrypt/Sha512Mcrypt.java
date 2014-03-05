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
 * | License: https://raw.github.com/eduosi/项目名称/master/LICENSE 									|
 * | Author: Yong.Teng <webmaster@buession.com> 													|
 * +------------------------------------------------------------------------------------------------+
 */
package com.buession.mcrypt;

import java.security.Provider;

public final class Sha512Mcrypt extends Mcrypt {

	public final static String ALGORITHM = "SHA-512";

	public Sha512Mcrypt() {
		super(ALGORITHM);
	}

	/**
	 * @param count
	 *        重复加密次数
	 */
	public Sha512Mcrypt(int count) {
		super(ALGORITHM, count);
	}

	/**
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Sha512Mcrypt(int count, Provider provider) {
		super(ALGORITHM, count, provider);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 */
	public Sha512Mcrypt(final String characterEncoding) {
		super(ALGORITHM, characterEncoding);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Sha512Mcrypt(final String characterEncoding, Provider provider) {
		super(ALGORITHM, characterEncoding, provider);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param count
	 *        重复加密次数
	 */
	public Sha512Mcrypt(final String characterEncoding, int count) {
		super(ALGORITHM, characterEncoding, count);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Sha512Mcrypt(final String characterEncoding, int count, Provider provider) {
		super(ALGORITHM, characterEncoding, count, provider);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 */
	public Sha512Mcrypt(final String characterEncoding, final String salt) {
		super(ALGORITHM, characterEncoding, salt);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Sha512Mcrypt(final String characterEncoding, final String salt, Provider provider) {
		super(ALGORITHM, characterEncoding, salt, provider);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param count
	 *        重复加密次数
	 */
	public Sha512Mcrypt(final String characterEncoding, final String salt, int count) {
		super(ALGORITHM, characterEncoding, salt, count);
	}

	/**
	 * @param characterEncoding
	 *        字符编码
	 * @param salt
	 *        加密密钥
	 * @param count
	 *        重复加密次数
	 * @param provider
	 *        信息摘要对象的提供者
	 */
	public Sha512Mcrypt(final String characterEncoding, final String salt, int count,
			Provider provider) {
		super(ALGORITHM, characterEncoding, salt, count, provider);
	}

}