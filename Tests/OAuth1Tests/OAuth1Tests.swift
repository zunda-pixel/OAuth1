import XCTest
@testable import OAuth1

final class OAuth1Tests: XCTestCase {
  let accessToken = "osFzw2dfZ2BYeJ8NhjRXZevBf"
  let accessSecretToken = "Gv71cgnPY6JkH0KW7oWYZnLmlmB1Bxd8rStr3mAPZ2dpdPAS1s"

  func testBearerToken() async throws {
    let url = URL(string: "https://api.twitter.com/oauth/request_token")!

    let oAuth1 = OAuth1(accessToken: accessToken, accessSecretToken: accessSecretToken, httpMethod: .post, url: url)
    
    let authorization = oAuth1.authorization()
    
    print(authorization)
  }
}
