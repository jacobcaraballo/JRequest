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

public final class JRequest<T: Decodable> {
	
	public enum JRequestMethod: String {
		case get, post
	}
	
	public init() {
		self.endpoint = ""
	}
	
	
	private let endpoint: String
	private var queries: [String: String]?
	private var headers: [String: String]?
	private var awsAuth: JRequestAuth?
	
	
	
	public init(endpoint: String) {
		self.endpoint = endpoint
	}
	
	public func set(query key: String, value: String) -> JRequest {
		if queries == nil { queries = [String: String]() }
		queries?[key] = value
		return self
	}
	
	public func set(header key: String, value: String) -> JRequest {
		if headers == nil { headers = [String: String]() }
		headers?[key] = value
		return self
	}
	
	public func set(awsAuth: JRequestAuth) -> JRequest {
		self.awsAuth = awsAuth
		return self
	}
	
	public func get(_ callback: @escaping (T?, JRequestError?) -> ()) {
		start(endpoint,
			  method: .get,
			  body: nil,
			  queries: queries,
			  headers: headers,
			  auth: awsAuth,
			  callback: callback)
	}
	
	public func post(body: [String: String]?, callback: @escaping (T?, JRequestError?) -> ()) {
		start(endpoint,
			  method: .get,
			  body: body,
			  queries: queries,
			  headers: headers,
			  auth: awsAuth,
			  callback: callback)
	}
	
	
	
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
	
	
	
	// MARK: GET Requests with decodable error
	public func get<E: Decodable>(
		_ endpoint: String,
		errorClass: E,
		queries: [String: String]? = nil,
		headers: [String: String]? = nil,
		auth: JRequestAuth? = nil,
		callback: @escaping ((T?, E?, JRequestError?) -> ())
	) {
		start(endpoint, method: .get, errorClass: errorClass, body: nil, queries: queries, headers: headers, auth: auth, callback: callback)
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
	
	
	
	// MARK: POST Requests with decodable error
	public func post<E: Decodable>(
		_ endpoint: String,
		errorClass: E,
		body: [String: Any]? = nil,
		queries: [String: String]? = nil,
		headers: [String: String]? = nil,
		auth: JRequestAuth? = nil,
		callback: @escaping ((T?, E?, JRequestError?) -> ())
	) {
		start(endpoint, method: .post, errorClass: errorClass, body: body, queries: queries, headers: headers, auth: auth, callback: callback)
	}
	
	
	
	private func request(
		_ endpoint: String,
		method: JRequestMethod,
		body: [String: Any]?,
		queries: [String: String]?,
		headers: [String: String]?,
		auth: JRequestAuth?,
		callback: @escaping ((Data?, JRequestError?) -> ())
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
		let task = URLSession.shared.dataTask(with: signedRequest) { data, res, error in
			
			guard error == nil
				else { return callback(nil, .networkError) }
			
			guard let data = data
				else { return callback(nil, .invalidResponse) }
			
			callback(data, nil)
		}
		task.resume()
		
	}
	
	
	
	/// Starts a request with the passed parameters.
	private func start(
		_ endpoint: String,
		method: JRequestMethod,
		body: [String: Any]?,
		queries: [String: String]?,
		headers: [String: String]?,
		auth: JRequestAuth?,
		callback: @escaping ((T?, JRequestError?) -> ())
	) {
		
		request(endpoint, method: method, body: body, queries: queries, headers: headers, auth: auth) { data, error in
			
			guard error == nil
				else { return callback(nil, .networkError) }
			
			guard let data = data
				else { return callback(nil, .invalidResponse) }
			
			guard !(T.self == String.self)
				else { return callback(String(data: data, encoding: .utf8) as? T, nil) }
			
			guard let response = try? JSONDecoder().decode(T.self, from: data)
				else { return callback(nil, .invalidResponse) }
			
			
			// the request was successful
			callback(response, nil)
		}
	}
	
	
	
	/// Starts a request with the parameters and checks for the error class.
	private func start<E: Decodable>(
		_ endpoint: String,
		method: JRequestMethod,
		errorClass: E,
		body: [String: Any]?,
		queries: [String: String]?,
		headers: [String: String]?,
		auth: JRequestAuth?,
		callback: @escaping ((T?, E?, JRequestError?) -> ())
	) {
		
		let decoder = JSONDecoder()
		request(endpoint, method: method, body: body, queries: queries, headers: headers, auth: auth) { data, error in
			
			guard error == nil
				else { return callback(nil, nil, .networkError) }
			
			guard let data = data
				else { return callback(nil, nil, .invalidResponse) }
			
			if E.self == String.self
			{ return callback(nil, String(data: data, encoding: .utf8) as? E, nil) }
			
			if let errorResponse = try? decoder.decode(E.self, from: data)
			{ return callback(nil, errorResponse, nil) }
			
			guard !(T.self == String.self)
				else { return callback(String(data: data, encoding: .utf8) as? T, nil, nil) }
			
			guard let response = try? decoder.decode(T.self, from: data)
				else { return callback(nil, nil, .invalidResponse) }
			
			
			// the request was successful
			callback(response, nil, nil)
		}
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
