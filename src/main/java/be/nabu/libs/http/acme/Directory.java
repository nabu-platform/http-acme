/*
* Copyright (C) 2017 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.http.acme;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;

import javax.xml.bind.annotation.XmlElement;

import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanResolver;

public class Directory {

	private URI keyChange, newAuthz, newCert, newReg, revokeCert;

	@XmlElement(name = "key-change")
	public URI getKeyChange() {
		return keyChange;
	}
	public void setKeyChange(URI keyChange) {
		this.keyChange = keyChange;
	}

	@XmlElement(name = "new-authz")
	public URI getNewAuthz() {
		return newAuthz;
	}
	public void setNewAuthz(URI newAuthz) {
		this.newAuthz = newAuthz;
	}

	@XmlElement(name = "new-cert")
	public URI getNewCert() {
		return newCert;
	}
	public void setNewCert(URI newCert) {
		this.newCert = newCert;
	}

	@XmlElement(name = "new-reg")
	public URI getNewReg() {
		return newReg;
	}
	public void setNewReg(URI newReg) {
		this.newReg = newReg;
	}

	@XmlElement(name = "revoke-cert")
	public URI getRevokeCert() {
		return revokeCert;
	}
	public void setRevokeCert(URI revokeCert) {
		this.revokeCert = revokeCert;
	}
	
	public static Directory parse(InputStream input) {
		try {
			try {
			JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(Directory.class), Charset.forName("UTF-8"));
			binding.setIgnoreUnknownElements(true);
			return TypeUtils.getAsBean(binding.unmarshal(input, new Window[0]), Directory.class);
			
			}
			finally {
				input.close();
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
