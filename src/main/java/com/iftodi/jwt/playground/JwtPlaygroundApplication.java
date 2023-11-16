package com.iftodi.jwt.playground;

import static java.util.stream.Collectors.joining;

import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;

public class JwtPlaygroundApplication {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	public static void main(String[] args) throws Exception {

		String privateKeyString = readKey("private.pem");
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

		NetSuiteRequest netSuiteRequest = new NetSuiteRequest(signedJwt);

		String requestBody = convertToUrlEncoded(netSuiteRequest);

		System.out.println("Request body:" + requestBody);
		HttpRequest request = HttpRequest.newBuilder()
			.uri(new URI("https://webhook.site/14caa4de-ce2b-410d-b4eb-4c0c0762e845"))
			.POST(HttpRequest.BodyPublishers.ofString(requestBody))
			.header("Content-Type", "application/x-www-form-urlencoded")
			.build();

		HttpClient httpClient = HttpClient.newHttpClient();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		System.out.println(response.body());
		System.out.println(response.headers().map());
	}

	private static String readKey(String classPathUrl) throws Exception {
		return new String(getKeyFromClassPathAsString(classPathUrl).getBytes(), StandardCharsets.ISO_8859_1);
	}

	private static String getKeyFromClassPathAsString(String classPathUrl) throws Exception {
		try (InputStream inputStream = new ClassPathResource(classPathUrl).getInputStream()) {
			return IOUtils.toString(inputStream, StandardCharsets.ISO_8859_1);
		}
	}

	private static String convertToUrlEncoded(Object objec) {
		Map<String, String> map = OBJECT_MAPPER.convertValue(objec, new TypeReference<Map<String, String>>() {
		});

		return map.keySet().stream()
			.map(key -> {
                String value =  String.valueOf(map.get(key));

                return value != null && !value.isEmpty()
                       ? key + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)
                       : null;
            })
			.filter(Objects::nonNull)
			.collect(joining("&"));
	}
}

