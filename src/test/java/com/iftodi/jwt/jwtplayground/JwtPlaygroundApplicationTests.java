package com.iftodi.jwt.jwtplayground;


import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

class JwtPlaygroundApplicationTests {

	@Test
	void validateJwt() throws Exception {

		String privateKeyString = readKey("private.pem");
		PublicKey publicKey = (PublicKey) toKey(readKey("public.pem").getBytes(StandardCharsets.ISO_8859_1));

		PrivateKey privateKey = new JcaPEMKeyConverter().getKeyPair(
			(PEMKeyPair) new PEMParser(new StringReader(privateKeyString)).readObject()).getPrivate();

		Date now = new Date();
		String signedJwt = Jwts.builder()
			.header()
			.add("typ", "JWT")
			.add("alg", "ES384")
			.add("kid", "H5IU2pC7KkKP21-qxjk3Cy")
			.and()
			.issuer("686fc7d507f974fd809f699b985272d4d3f5")
			.claim("scope", "rest_webservices")
			.audience()
			.add("https://webhook.site/14caa4de-ce2b-410d-b4eb-4c0c0762e845")
			.and()
			.issuedAt(now)
			.expiration(Date.from(now.toInstant().plusSeconds(300)))
			.signWith(privateKey)
			.compact();

		Jwt<?, ?> jwtParsed = Jwts.parser()
			.verifyWith(publicKey)
			.build()
			.parse(signedJwt);

		assertThat(jwtParsed).isNotNull();
	}

	private static Key toKey(byte[] key) throws Exception {
		try {
			return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(key));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			PemReader pemReader = new PemReader(new StringReader(new String(key)));
			try {
				PemObject pemObject = pemReader.readPemObject();
				if (pemObject == null) {
					throw new InvalidKeyException("Invalid EC key");
				}
				return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
			} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException exception) {
				try {
					return new JcaPEMKeyConverter().getKeyPair(
						(PEMKeyPair) new PEMParser(new StringReader(
							new String(key, StandardCharsets.ISO_8859_1))).readObject()).getPrivate();
				} catch (IOException ex) {
					throw new InvalidKeyException("Invalid EC key", ex);
				}
			}
		}
	}

	private static String readKey(String classPathUrl) throws Exception {
		return new String(getKeyFromClassPathAsString(classPathUrl).getBytes(), StandardCharsets.ISO_8859_1);
	}

	private static String getKeyFromClassPathAsString(String classPathUrl) throws Exception {
		try (InputStream inputStream = new ClassPathResource(classPathUrl).getInputStream()) {
			return IOUtils.toString(inputStream, StandardCharsets.ISO_8859_1);
		}
	}
}
