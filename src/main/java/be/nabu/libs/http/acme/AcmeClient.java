package be.nabu.libs.http.acme;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.client.HTTPClient;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.map.MapContent;
import be.nabu.libs.types.map.MapContentWrapper;
import be.nabu.libs.types.map.MapTypeGenerator;
import be.nabu.libs.types.utils.DateTimeFormat;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.SignatureType;

// based in part on https://github.com/shred/acme4j
// note that you have a user keypair that is for the account, but your csr _have_ to come from another keypair
public class AcmeClient {
	public static final String LETS_ENCRYPT = "https://acme-v01.api.letsencrypt.org/directory";
	public static final String LETS_ENCRYPT_STAGING = "https://acme-staging.api.letsencrypt.org/directory";
	
	public enum ChallengeType { HTTP, DNS, TLS_SNI };
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	private HTTPClient client;
	
	private String nonce;
	private URI location;
	
	// terms-of-service
	// next
	private Map<String, URI> links = new HashMap<String, URI>();
	
	private long time = 3;
	private TimeUnit timeUnit = TimeUnit.SECONDS;
	private int amount = 10;
	private KeyPair user;
	private Directory directory;
	private URI directoryUri;
	private int maxChainSize = 10;
	
	public AcmeClient(HTTPClient client, KeyPair user, URI directory) {
		this.client = client;
		this.user = user;
		this.directoryUri = directory;
	}
	
	private Directory getDirectory() {
		if (directory == null) {
			synchronized(this) {
				if (directory == null) {
					Directory directory = directory(directoryUri);
					try {
						// we create a new account linked to the key pair
						register(directory, user);
						// each new account must accept the tos
						acceptAgreement(user);
					}
					catch (Exception e) {
						logger.debug("Registration failed, possibly already exists for this key");
					}
					this.directory = directory;
				}
			}
		}
		return directory;
	}
	
	@SuppressWarnings("unchecked")
	public Challenge challenge(String domain, ChallengeType type) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("resource", "new-authz");
		Map<String, Object> identifier = new HashMap<String, Object>();
		identifier.put("type", "dns");
		identifier.put("value", SecurityUtils.encodeAce(domain));
		map.put("identifier", identifier);
		HTTPResponse response = executeSecure(getDirectory().getNewAuthz(), stringify(map), user);
		ComplexContent content = parse(response);
		String challengeType = type.toString().toLowerCase().replace("_", "-");
		for (ComplexContent challenge : (List<ComplexContent>) content.get("challenges")) {
			if (((String) challenge.get("type")).startsWith(challengeType)) {
				try {
					Challenge c = new Challenge(this, challenge, user, new DateTimeFormat().parse((String) content.get("expires")), domain);
					// if already valid, don't return a challenge
					return "valid".equalsIgnoreCase(c.getStatus()) ? null : c;
				}
				catch (Exception e) {
					throw new RuntimeException(e);
				}
			}
		}
		throw new RuntimeException("No challenge found of type: " + type);
	}
	
	protected void accept(Challenge challenge) {
		Map<String, Object> content = new HashMap<String, Object>();
		content.put("resource", "challenge");
		content.put("keyAuthorization", challenge.getAuthorization());
		HTTPResponse response = executeSecure(challenge.getUri(), stringify(content), challenge.getPair());
		challenge.update(parse(response));
		int amount = 0;
		while (!challenge.accepted() && !challenge.rejected()) {
			if (amount >= this.amount) {
				throw new RuntimeException("Could not validate the challenge in time, current state: " + challenge.getStatus());
			}
			try {
				Thread.sleep(TimeUnit.MILLISECONDS.convert(time, timeUnit));
			}
			catch (InterruptedException e) {
				// ignore
			}
			HTTPResponse execute = execute(new DefaultHTTPRequest("GET", challenge.getUri().getPath(), new PlainMimeEmptyPart(null, 
				new MimeHeader("Content-Length", "0"),
				new MimeHeader("Host", challenge.getUri().getAuthority()))), challenge.getUri().getScheme().equals("https"));
			challenge.update(parse(execute));

			amount++;
		}
	}
	
	public X509Certificate[] certify(String domain, KeyPair pair, SignatureType type, X500Principal subject, Date notBefore, Date notAfter, String...alternateDomains) {
		try {
			Map<String, String> parts = SecurityUtils.getParts(subject);
			X500Principal principal = SecurityUtils.createX500Principal(domain, parts.get("O"), parts.get("OU"), parts.get("L"), parts.get("ST"), parts.get("C"));
			byte[] pkcs10 = BCSecurityUtils.generatePKCS10(pair, type, principal, alternateDomains);
			Map<String, Object> map = new HashMap<String, Object>();
			map.put("notBefore", new DateTimeFormat().format(notBefore));
			map.put("notAfter", new DateTimeFormat().format(notAfter));
			map.put("csr", Base64Url.encode(pkcs10));
			map.put("resource", "new-cert");
			HTTPResponse response = executeSecure(getDirectory().getNewCert(), stringify(map), user);
			if (!"application/pkix-cert".equals(MimeUtils.getContentType(response.getContent().getHeaders()))) {
				throw new RuntimeException("Wrong content type: " + MimeUtils.getContentType(response.getContent().getHeaders()));
			}
			ReadableContainer<ByteBuffer> readable = ((ContentPart) response.getContent()).getReadable();
			List<X509Certificate> certificates = new ArrayList<X509Certificate>();
			try {
				// get the actual certificate
				certificates.add(SecurityUtils.parseCertificate(IOUtils.toInputStream(readable)));
				// try to resolve the chain
				while (certificates.size() < maxChainSize && links.get("up") != null) {
					URI uri = links.remove("up");
					response = execute(new DefaultHTTPRequest("GET", uri.getPath(), new PlainMimeEmptyPart(null,
						new MimeHeader("Content-Length", "0"),
						new MimeHeader("Host", uri.getAuthority()))), uri.getScheme().equals("https"));
					readable = ((ContentPart) response.getContent()).getReadable();
					certificates.add(SecurityUtils.parseCertificate(IOUtils.toInputStream(readable)));
				}
			}
			finally {
				readable.close();
			}
			return certificates.toArray(new X509Certificate[certificates.size()]);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private ComplexContent parse(HTTPResponse response) {
		try {
			return parse(IOUtils.toInputStream(((ContentPart) response.getContent()).getReadable()));
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private ComplexContent parse(InputStream input) {
		JSONBinding binding = new JSONBinding(new MapTypeGenerator(), Charset.forName("UTF-8"));
		binding.setAddDynamicElementDefinitions(true);
		binding.setAllowDynamicElements(true);
		try {
			try {
				return binding.unmarshal(input, new Window[0]);
			}
			finally {
				input.close();
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private String stringify(Map<String, Object> content) {
		try {
			MapContent map = new MapContent(MapContentWrapper.buildFromContent(content), content);
			JSONBinding binding = new JSONBinding(map.getType(), Charset.forName("UTF-8"));
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			binding.marshal(output, map);
			return new String(output.toByteArray(), "UTF-8");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private void processLinks(HTTPResponse response) {
		Header[] headers = MimeUtils.getHeaders("Link", response.getContent().getHeaders());
		if (headers != null) {
			for (Header header : headers) {
				try {
					String link = header.getValue().replaceAll(".*?<([^>]+)>.*", "$1");
					String name = header.getComments()[0].replaceAll("rel=(.*)", "$1").replace("\"", "");
					links.put(name, new URI(link));
				}
				catch (Exception e) {
					logger.error("Invalid link: " + header.getValue(), e);
				}
			}
		}
	}
	
	private HTTPResponse execute(HTTPRequest request, boolean secure) {
		try {
			HTTPResponse response = client.execute(request, null, secure, true);
			nonce = nonce(response);
			processLinks(response);

			Header header = MimeUtils.getHeader("Location", response.getContent().getHeaders());
			if (header != null) {
				this.location = new URI(header.getValue());
			}
			
			if (response.getCode() >= 300) {
				throw new IllegalStateException("Received error from server: " + response.getCode());
			}
			return response;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private Directory directory(URI uri) {
		try {
			logger.info("Retrieving directory from: " + uri);
			HTTPResponse response = execute(new DefaultHTTPRequest("GET", uri.getPath(), new PlainMimeEmptyPart(null, 
				new MimeHeader("Content-Length", "0"),
				new MimeHeader("Host", uri.getAuthority()))), uri.getScheme().equals("https"));
			
			Directory directory = Directory.parse(IOUtils.toInputStream(((ContentPart) response.getContent()).getReadable()));
			logger.info("New registration: " + directory.getNewReg());
			logger.info("New authorization: " + directory.getNewAuthz());
			logger.info("New certificate: " + directory.getNewCert());
			logger.info("Revoke certificate: " + directory.getRevokeCert());
			logger.info("Key Exchange: " + directory.getKeyChange());
			return directory;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	// returns a 405 not allowed, only POST is allowed
	@SuppressWarnings("unused")
	private String nonce(URI uri) {
		try {
			logger.info("Getting nonce for: " + uri);
			HTTPResponse response = execute(new DefaultHTTPRequest("HEAD", uri.getPath(), new PlainMimeEmptyPart(null, 
				new MimeHeader("Content-Length", "0"),
				new MimeHeader("Host", uri.getAuthority()),
				new MimeHeader("Accept-Language", "en"))), uri.getScheme().equals("https"));
			return nonce(response);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private String nonce(HTTPResponse response) {
		Header header = MimeUtils.getHeader("Replay-Nonce", response.getContent().getHeaders());
		if (header == null) {
			throw new RuntimeException("No nonce header found");
		}
		return header.getValue();
	}
	
	private void register(Directory directory, KeyPair pair) {
		try {
			logger.info("Registering at: " + directory.getNewReg());
			Map<String, Object> content = new HashMap<String, Object>();
			content.put("resource", "new-reg");
			executeSecure(directory.getNewReg(), stringify(content), pair);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private HTTPResponse executeSecure(URI uri, String json, KeyPair pair) {
		try {
			final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(pair.getPublic());
			JsonWebSignature jws = new JsonWebSignature();
			jws.setPayload(json);
			jws.getHeaders().setObjectHeaderValue("nonce", nonce);
			jws.getHeaders().setObjectHeaderValue("url", uri);
			jws.getHeaders().setJwkHeaderValue("jwk", jwk);
			jws.setAlgorithmHeaderValue(AcmeUtils.keyAlgorithm(jwk));
			jws.setKey(pair.getPrivate());
			byte[] data = jws.getCompactSerialization().getBytes("UTF-8");
			return execute(new DefaultHTTPRequest("POST", uri.getPath(), new PlainMimeContentPart(null, 
				IOUtils.wrap(data, true), 
				new MimeHeader("Content-Length", "" + data.length),
				new MimeHeader("Host", uri.getAuthority()),
				new MimeHeader("Content-Type", "application/jose+json"))), uri.getScheme().equals("https"));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private void acceptAgreement(KeyPair pair) {
		logger.info("Accepting agreement");
		if (links.get("terms-of-service") == null) {
			throw new IllegalStateException("No terms of service link found");
		}
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("resource", "reg");
		map.put("agreement", links.get("terms-of-service"));
		executeSecure(location, stringify(map), pair);
	}
}
