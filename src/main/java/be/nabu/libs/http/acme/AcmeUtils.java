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
	
	public static URI getHttpUri(Challenge challenge) {
		try {
			return new URI("http://" + challenge.getDomain() + "/.well-known/acme-challenge/" + challenge.getToken());
		}
		catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
}
