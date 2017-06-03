package be.nabu.libs.http.acme;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanResolver;

@XmlRootElement(name = "directory")
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
