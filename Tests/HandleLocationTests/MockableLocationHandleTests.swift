import CoreLocation
import HandleLocation
import Mockable
import XCTest

final class MockableLocationHandleTests: XCTestCase {
  @MainActor
  func testMockableCanMockLocationProtocol() async throws {
    let handle = LocationHandle.Mock()
    let location = CLLocation(latitude: 46.0569, longitude: 14.5058)

    given(handle)
      .currentLocation(options: .any)
      .willReturn(location)

    let received = try await handle.currentLocation(options: .init())

    XCTAssertEqual(received, location)
    verify(handle)
      .currentLocation(options: .any)
      .called(.once)
  }

  @MainActor
  func testMockableCanMockGeocoderProtocol() async throws {
    let geocoder = LocationHandle.Geocoder.Mock()
    let placemark = LocationHandle.Placemark(locality: "Ljubljana", country: "Slovenia")

    given(geocoder)
      .reverseGeocode(.any)
      .willReturn(placemark)

    let received = try await geocoder.reverseGeocode(CLLocation(latitude: 46.0569, longitude: 14.5058))

    XCTAssertEqual(received, placemark)
    verify(geocoder)
      .reverseGeocode(.any)
      .called(.once)
  }
}
