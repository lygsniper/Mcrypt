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

public class DoubleMD5Mcrypt {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Mcrypt mcrypt = new MD5Mcrypt("UTF-8", Constants.SALT, 2);

		System.out.println(mcrypt.encode(Constants.STR));
	}

}