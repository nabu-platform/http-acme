package be.nabu.libs.http.acme;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;

import be.nabu.libs.types.api.ComplexContent;

// states are: PENDING, PROCESSING, VALID, INVALID, REVOKED, DEACTIVATED, GOOD, UNKNOWN
public class Challenge {
	
	private ComplexContent content;
	private KeyPair pair;
	private Date expires;
	private AcmeClient client;
	private String domain;

	Challenge(AcmeClient client, ComplexContent content, KeyPair pair, Date expires, String domain) {
		this.client = client;
		this.content = content;
		this.pair = pair;
		this.expires = expires;
		this.domain = domain;
	}
	
	public Date getExpires() {
		return expires;
	}

	public String getAuthorization() {	
		PublicKey pk = pair.getPublic();
		try {
			PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(pk);
			return getToken() + "." + Base64Url.encode(jwk.calculateThumbprint("SHA-256"));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public String getToken() {
		return (String) content.get("token");
	}
	
	public String getStatus() {
		return (String) content.get("status");
	}
	
	public URI getUri() {
		try {
			return new URI((String) content.get("uri"));
		}
		catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public String getDomain() {
		return domain;
	}
	
	public void accept() {
		client.accept(this);
	}

	KeyPair getPair() {
		return pair;
	}
	
	public boolean accepted() {
		return "valid".equalsIgnoreCase((String) content.get("status"));
	}
	
	public boolean rejected() {
		return "invalid".equalsIgnoreCase((String) content.get("status"));
	}
	
	void update(ComplexContent content) {
		this.content = content;
	}
}
