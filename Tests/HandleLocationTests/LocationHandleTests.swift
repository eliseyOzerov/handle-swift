import CoreLocation
import HandleLocation
import XCTest

final class LocationHandleTests: XCTestCase {
  @MainActor
  func testLocationTestReturnsConfiguredLocationAndPlace() async throws {
    let location = CLLocation(latitude: 46.0569, longitude: 14.5058)
    let placemark = LocationHandle.Placemark(
      locality: "Ljubljana",
      country: "Slovenia",
      coordinate: .init(latitude: 46.0569, longitude: 14.5058)
    )
    let handle = LocationHandle.Test(
      authorizationStatus: .authorizedWhenInUse,
      location: location,
      placemark: placemark
    )

    let receivedLocation = try await handle.currentLocation()
    let receivedPlace = try await handle.currentPlace()

    XCTAssertEqual(receivedLocation, location)
    XCTAssertEqual(receivedPlace.city, "Ljubljana")
    XCTAssertEqual(receivedPlace.country, "Slovenia")
    XCTAssertEqual(handle.currentLocationCallCount, 1)
    XCTAssertEqual(handle.currentPlaceCallCount, 1)
  }

  @MainActor
  func testLocationTestStreamsAuthorizationAndLocationUpdates() async throws {
    let handle = LocationHandle.Test()
    var authorizationIterator = handle.authorizationUpdates().makeAsyncIterator()
    var locationIterator = handle.locationUpdates().makeAsyncIterator()
    let location = CLLocation(latitude: 46.5547, longitude: 15.6459)

    let initialAuthorization = await authorizationIterator.next()
    XCTAssertEqual(initialAuthorization, .notDetermined)

    handle.setAuthorizationStatus(.authorizedWhenInUse)
    handle.setCurrentLocation(location)

    let updatedAuthorization = await authorizationIterator.next()
    let updatedLocation = await locationIterator.next()
    XCTAssertEqual(updatedAuthorization, .authorizedWhenInUse)
    XCTAssertEqual(updatedLocation, location)
  }

  @MainActor
  func testGeocoderTestReturnsConfiguredPlacemark() async throws {
    let geocoder = LocationHandle.Geocoder.Test()
    let placemark = LocationHandle.Placemark(locality: "Maribor", country: "Slovenia")
    geocoder.setPlacemark(placemark)

    let received = try await geocoder.reverseGeocode(CLLocation(latitude: 46.5547, longitude: 15.6459))

    XCTAssertEqual(received, placemark)
    XCTAssertEqual(geocoder.reverseGeocodeCallCount, 1)
  }
}
