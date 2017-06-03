package be.nabu.libs.http.acme;

import java.net.URI;
import java.net.URISyntaxException;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;

public class AcmeUtils {
	
	public static String keyAlgorithm(JsonWebKey jwk) {
		if (jwk instanceof EllipticCurveJsonWebKey) {
			EllipticCurveJsonWebKey ecjwk = (EllipticCurveJsonWebKey) jwk;
			switch (ecjwk.getCurveName()) {
				case "P-256":
					return AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
				case "P-384":
					return AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;
				case "P-521":
					return AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;
				default:
					throw new IllegalArgumentException("Unknown EC name " + ecjwk.getCurveName());
			}
		}
		else if (jwk instanceof RsaJsonWebKey) {
			return AlgorithmIdentifiers.RSA_USING_SHA256;

		}
		else {
			throw new IllegalArgumentException("Unknown algorithm " + jwk.getAlgorithm());
		}
	}
	
	public URI getHTTPUri(Challenge challenge) {
		try {
			return new URI("http://" + challenge.getDomain() + "/.well-known/acme-challenge/" + challenge.getToken());
		}
		catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
}
