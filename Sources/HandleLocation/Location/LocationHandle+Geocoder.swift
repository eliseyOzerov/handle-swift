import CoreLocation
import Foundation
import Mockable

extension LocationHandle {
  /// Async reverse geocoding handle.
  public class Geocoder: @unchecked Sendable {
    public static let shared = Geocoder()

    public init() {}

    @MainActor
    open func reverseGeocode(_ location: CLLocation) async throws -> Placemark {
      let placemarks = try await CLGeocoder().reverseGeocodeLocation(location)
      guard let placemark = placemarks.first else {
        throw LocationHandle.Error.placeUnavailable
      }
      return Placemark(placemark)
    }
  }
}

extension LocationHandle.Geocoder {
  @Mockable
  public protocol Interface: Sendable {
    @MainActor
    func reverseGeocode(_ location: CLLocation) async throws -> LocationHandle.Placemark
  }

  #if MOCKING
  public typealias Mock = MockInterface
  #endif

  public enum TestError: Swift.Error, Sendable, Equatable {
    case unhandledReverseGeocode
  }

  public struct ReverseGeocodeCall: Sendable {
    public let location: CLLocation
  }

  /// Test geocoder with configurable returns, errors, and call recording.
  public final class Test: LocationHandle.Geocoder, @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<LocationHandle.Placemark, Swift.Error>?
    private var recordedReverseGeocodeCalls: [ReverseGeocodeCall] = []

    public override init() {
      super.init()
    }

    public var reverseGeocodeCallCount: Int {
      lock.withLock { recordedReverseGeocodeCalls.count }
    }

    public var reverseGeocodeCalls: [ReverseGeocodeCall] {
      lock.withLock { recordedReverseGeocodeCalls }
    }

    public func setPlacemark(_ placemark: LocationHandle.Placemark) {
      lock.withLock {
        result = .success(placemark)
      }
    }

    public func setReverseGeocodeError(_ error: Swift.Error) {
      lock.withLock {
        result = .failure(error)
      }
    }

    @MainActor
    override public func reverseGeocode(_ location: CLLocation) async throws -> LocationHandle.Placemark {
      let result = lock.withLock {
        recordedReverseGeocodeCalls.append(ReverseGeocodeCall(location: location))
        return self.result
      }

      guard let result else {
        throw TestError.unhandledReverseGeocode
      }

      return try result.get()
    }
  }
}

extension LocationHandle.Geocoder: LocationHandle.Geocoder.Interface {}
