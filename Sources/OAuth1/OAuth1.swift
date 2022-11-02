//
//  OAuth1.swift
//

import Foundation

#if os(Linux) || os(Windows)
  import Crypto
#else
  import CryptoKit
#endif

public struct OAuth1 {
  private let accessToken: String
  private let accessSecretToken: String
  
  private let oAuthToken: String?
  private let oAuthSecretToken: String
  
  let url: URL
  let httpMethod: String
  let queries: [String: String]
  
  private let oAuthVersion = "1.0"
  private let signatureMethod = "HMAC-SHA1"
  
  private let nonce = UUID().uuidString
  private var timestamp: String { String(Int(Date().timeIntervalSince1970)) }
  
  public init(accessToken: String, accessSecretToken: String, oAuthToken: String? = nil, oAuthSecretToken: String = "", httpMethod: String, url: URL, queries: [String: String] = [:]) {
    self.accessToken = accessToken
    self.accessSecretToken = accessSecretToken
    
    self.oAuthToken = oAuthToken
    self.oAuthSecretToken = oAuthSecretToken
    
    self.httpMethod = httpMethod
    self.url = url
    self.queries = queries
  }
  
  private var parameters: [String: String] {
    var parameters = [
      "oauth_consumer_key": accessToken,
      "oauth_signature_method": signatureMethod,
      "oauth_timestamp": timestamp,
      "oauth_nonce": nonce,
      "oauth_version": oAuthVersion,
    ]
    
    if let oAuthToken {
      parameters["oauth_token"] = oAuthToken
    }
    
    return parameters.merging(queries) { current, _ in current }
  }
  
  private var parameterString: String {
    let encodedValues = parameters.map {($0.urlEncoded, $1.urlEncoded)}
    let dictionary = encodedValues.reduce(into: [String: String]()) { $0[$1.0] = $1.1 }
    let sortedValues = dictionary.sorted { $0.0 < $1.0 } .map { $0 }
    let eachJoinedValues = sortedValues.map { "\($0)=\($1)" }
    let joinedValue = eachJoinedValues.joined(separator: "&")
    return joinedValue
  }
  
  private var baseParameters: [String] {
    [
      httpMethod,
      url.absoluteString,
      parameterString,
    ]
  }
  
  private var baseString: String {
    let encodedValues = baseParameters.map{ $0.urlEncoded }
    let joinedValue = encodedValues.joined(separator: "&")
    return joinedValue
  }
  
  private var key: String {
    return "\(accessSecretToken.urlEncoded)&\(oAuthSecretToken.urlEncoded)"
  }
  
  private func signature(key: String, message: String) -> String {
    let key = SymmetricKey(data: key.data(using: .utf8)!)
    let signature = HMAC<Insecure.SHA1>.authenticationCode(for: message.data(using: .utf8)!, using: key)
    let signatureString = Data(signature).base64EncodedString(options: .lineLength64Characters)
    return signatureString
  }
  
  public func bearerToken() -> String {
    let signature = signature(key: key, message: baseString)
    let values =  ["oauth_signature": signature]
    
    let parameters = parameters.merging(values) { (current, _) in current }
    let joinedParameters = parameters.map{"\($0.urlEncoded)=\"\($1.urlEncoded)\""}
    let bearerToken = "OAuth \(joinedParameters.joined(separator: ","))"
    return bearerToken
  }
}

private extension String {
  var urlEncoded: String {
    let allowedCharacters = CharacterSet.alphanumerics.union(.init(charactersIn: "-._~"))
    return self.addingPercentEncoding(withAllowedCharacters: allowedCharacters)!
  }
}
