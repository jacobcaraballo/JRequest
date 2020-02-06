//
//  JRequest.swift
//  Money Pro
//
//  Created by Jacob Caraballo on 1/8/20.
//  Copyright © 2020 Jacob Caraballo. All rights reserved.
//

import Foundation
import CryptoSwift

public final class JRequestAuth {
	
	public let key: String
	public let secret: String
	public let region: String
	
	public init(key: String, secret: String, region: String = "us-east-1") {
		self.key = key
		self.secret = secret
		self.region = region
	}
	
}

public enum JRequestError: Error {
	case invalidURL
	case networkError
	case invalidResponse
}

public final class JRequest<T: Codable> {
	
	public enum JRequestMethod: String {
		case get, post
	}
	
	public init() { }
	
	
	
	// MARK: GET Requests
	public func get(
		_ endpoint: String,
		queries: [String: String]? = nil,
		headers: [String: String]? = nil,
		auth: JRequestAuth? = nil,
		callback: @escaping ((T?, JRequestError?) -> ())
	) {
		start(endpoint, method: .get, body: nil, queries: queries, headers: headers, auth: auth, callback: callback)
	}
	
	
	
	// MARK: POST Requests
	public func post(
		_ endpoint: String,
		body: [String: Any]? = nil,
		queries: [String: String]? = nil,
		headers: [String: String]? = nil,
		auth: JRequestAuth? = nil,
		callback: @escaping ((T?, JRequestError?) -> ())
	) {
		start(endpoint, method: .post, body: body, queries: queries, headers: headers, auth: auth, callback: callback)
	}
	
	
	
	private func start(
		_ endpoint: String,
		method: JRequestMethod,
		body: [String: Any]?,
		queries: [String: String]?,
		headers: [String: String]?,
		auth: JRequestAuth?,
		callback: @escaping ((T?, JRequestError?) -> ())
	) {
		
		// set query items
		guard var comps = URLComponents(string: endpoint) else { return callback(nil, .invalidURL) }
		comps.queryItems = queries?.map({ URLQueryItem(name: $0, value: $1) })
		
		
		// create request with components
		guard let url = comps.url else { return callback(nil, .invalidURL)}
		var request = URLRequest(url: url)
		request.httpMethod = method.rawValue.uppercased()
		
		if let body = body, let data = try? JSONSerialization.data(withJSONObject: body) {
			request.httpBody = data
		}
		
		// set headers
		if let headers = headers {
			for (key, value) in headers {
				request.setValue(value, forHTTPHeaderField: key)
			}
		}
		
		
		// set default content-type
		if request.value(forHTTPHeaderField: "Content-Type") == nil {
			request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		}
		
		
		// sign the request if necessary
		var signedRequest = request
		if let auth = auth, let signed = JRequestSigner.sign(request: request, secret: auth.secret, key: auth.key, awsRegion: auth.region) {
			signedRequest = signed
		}
		
		
		// start task with the request and fetch the json response
		let decoder = JSONDecoder()
		let task = URLSession.shared.dataTask(with: signedRequest) { data, res, error in
			
			guard error == nil
				else { return callback(nil, .networkError) }
			
			guard let data = data
				else { return callback(nil, .invalidResponse) }
			
			guard !(T.self == String.self)
				else { return callback(String(data: data, encoding: .utf8) as? T, nil) }
			
			guard let response = try? decoder.decode(T.self, from: data)
				else { return callback(nil, .invalidResponse) }
			
			
			// the request was successful
			callback(response, nil)
		}
		task.resume()
	}
	
}


private class JRequestSigner: NSObject {
	
	private static let hmacShaTypeString = "AWS4-HMAC-SHA256"
	private static let serviceType = "execute-api"
	private static let aws4Request = "aws4_request"
	
	private static var isoDate: (full: String, short: String) {
		let formatter = DateFormatter()
		formatter.calendar = Calendar(identifier: .iso8601)
		formatter.locale = Locale(identifier: "en_US_POSIX")
		formatter.timeZone = TimeZone(secondsFromGMT: 0)
		formatter.dateFormat = "yyyyMMdd'T'HHmmssXXXXX"
		
		let date = formatter.string(from: Date())
		let shortDate = String(date.prefix(8))
		return (full: date, short: shortDate)
	}
	
	
	class func sign(request: URLRequest, secret: String, key: String, awsRegion: String = "us-east-1") -> URLRequest? {
		var signedRequest = request
		let date = isoDate
		
		var body = ""
		if let bodyData = signedRequest.httpBody {
			body = String(data: bodyData, encoding: .utf8) ?? ""
		}
		guard let url = signedRequest.url, let host = url.host
			else { return .none }
		
		signedRequest.addValue(host, forHTTPHeaderField: "Host")
		signedRequest.addValue(date.full, forHTTPHeaderField: "X-Amz-Date")
		
		guard let headers = signedRequest.allHTTPHeaderFields, let method = signedRequest.httpMethod
			else { return .none }
		
		let signedHeaders = headers.map{ $0.key.lowercased() }.sorted().joined(separator: ";")
		
		let canonicalRequestHash = [
			method,
			url.path,
			url.query ?? "",
			headers.map{ $0.key.lowercased() + ":" + $0.value }.sorted().joined(separator: "\n"),
			"",
			signedHeaders,
			body.sha256()
			].joined(separator: "\n").sha256()
		
		let credential = [date.short, awsRegion, serviceType, aws4Request].joined(separator: "/")
		
		let stringToSign = [
			hmacShaTypeString,
			date.full,
			credential,
			canonicalRequestHash
			].joined(separator: "\n")
		
		guard let signature = hmacStringToSign(stringToSign: stringToSign, secretSigningKey: secret, shortDateString: date.short, awsRegion: awsRegion)
			else { return .none }
		
		let authorization = hmacShaTypeString + " Credential=" + key + "/" + credential + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
		signedRequest.addValue(authorization, forHTTPHeaderField: "Authorization")
		
		return signedRequest
	}
	
	private class func hmacStringToSign(stringToSign: String, secretSigningKey: String, shortDateString: String, awsRegion: String) -> String? {
		let k1 = "AWS4" + secretSigningKey
		guard let sk1 = try? HMAC(key: [UInt8](k1.utf8), variant: .sha256).authenticate([UInt8](shortDateString.utf8)),
			let sk2 = try? HMAC(key: sk1, variant: .sha256).authenticate([UInt8](awsRegion.utf8)),
			let sk3 = try? HMAC(key: sk2, variant: .sha256).authenticate([UInt8](serviceType.utf8)),
			let sk4 = try? HMAC(key: sk3, variant: .sha256).authenticate([UInt8](aws4Request.utf8)),
			let signature = try? HMAC(key: sk4, variant: .sha256).authenticate([UInt8](stringToSign.utf8)) else { return .none }
		return signature.toHexString()
	}
	
}
