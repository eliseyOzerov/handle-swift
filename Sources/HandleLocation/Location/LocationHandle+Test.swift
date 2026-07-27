import CoreLocation
import Foundation

extension LocationHandle {
  public enum TestError: Swift.Error, Sendable, Equatable {
    case unhandledCurrentLocation
    case unhandledCurrentPlace
    case unhandledReverseGeocode
  }

  public struct CurrentLocationCall: Sendable, Equatable {
    public let options: RequestOptions
  }

  public struct CurrentPlaceCall: Sendable, Equatable {
    public let options: RequestOptions
  }

  public struct ReverseGeocodeCall: Sendable {
    public let location: CLLocation
  }

  /// Test location handle with local permission/location state, streams, and call recording.
  public final class Test: LocationHandle, @unchecked Sendable {
    private let lock = NSLock()
    private var storedAuthorizationStatus: AuthorizationStatus = .notDetermined
    private var storedLocation: CLLocation?
    private var storedPlacemark: Placemark?
    private var locationResult: Result<CLLocation, Swift.Error>?
    private var placeResult: Result<Place, Swift.Error>?
    private var reverseGeocodeResult: Result<Placemark, Swift.Error>?
    private var authorizationStreamContinuations: [UUID: AsyncStream<AuthorizationStatus>.Continuation] = [:]
    private var locationStreamContinuations: [UUID: AsyncStream<CLLocation>.Continuation] = [:]
    private var recordedCurrentLocationCalls: [CurrentLocationCall] = []
    private var recordedCurrentPlaceCalls: [CurrentPlaceCall] = []
    private var recordedReverseGeocodeCalls: [ReverseGeocodeCall] = []
    private var requestWhenInUseAuthorizationCallCountValue = 0
    private var isRequestingLocationValue = false

    public init(
      authorizationStatus: AuthorizationStatus = .notDetermined,
      location: CLLocation? = nil,
      placemark: Placemark? = nil
    ) {
      storedAuthorizationStatus = authorizationStatus
      storedLocation = location
      storedPlacemark = placemark
      super.init(geocoder: LocationHandle.Geocoder.Test())
    }

    @MainActor
    override public var authorizationStatus: AuthorizationStatus {
      lock.withLock { storedAuthorizationStatus }
    }

    @MainActor
    override public var latestLocation: CLLocation? {
      lock.withLock { storedLocation }
    }

    @MainActor
    override public var isRequestingLocation: Bool {
      lock.withLock { isRequestingLocationValue }
    }

    public var currentLocationCallCount: Int {
      lock.withLock { recordedCurrentLocationCalls.count }
    }

    public var currentPlaceCallCount: Int {
      lock.withLock { recordedCurrentPlaceCalls.count }
    }

    public var reverseGeocodeCallCount: Int {
      lock.withLock { recordedReverseGeocodeCalls.count }
    }

    public var requestWhenInUseAuthorizationCallCount: Int {
      lock.withLock { requestWhenInUseAuthorizationCallCountValue }
    }

    public var currentLocationCalls: [CurrentLocationCall] {
      lock.withLock { recordedCurrentLocationCalls }
    }

    public var currentPlaceCalls: [CurrentPlaceCall] {
      lock.withLock { recordedCurrentPlaceCalls }
    }

    public var reverseGeocodeCalls: [ReverseGeocodeCall] {
      lock.withLock { recordedReverseGeocodeCalls }
    }

    public func setAuthorizationStatus(_ status: AuthorizationStatus) {
      let continuations = lock.withLock {
        storedAuthorizationStatus = status
        return Array(authorizationStreamContinuations.values)
      }
      for continuation in continuations {
        continuation.yield(status)
      }
    }

    public func setCurrentLocation(_ location: CLLocation?) {
      let continuations = lock.withLock {
        storedLocation = location
        guard location != nil else { return [AsyncStream<CLLocation>.Continuation]() }
        return Array(locationStreamContinuations.values)
      }
      if let location {
        for continuation in continuations {
          continuation.yield(location)
        }
      }
    }

    public func setCurrentLocationError(_ error: Swift.Error) {
      lock.withLock {
        locationResult = .failure(error)
      }
    }

    public func setPlacemark(_ placemark: Placemark?) {
      lock.withLock {
        storedPlacemark = placemark
      }
    }

    public func setReverseGeocode(_ placemark: Placemark) {
      lock.withLock {
        reverseGeocodeResult = .success(placemark)
      }
    }

    public func setReverseGeocodeError(_ error: Swift.Error) {
      lock.withLock {
        reverseGeocodeResult = .failure(error)
      }
    }

    public func setCurrentPlace(_ place: Place) {
      lock.withLock {
        placeResult = .success(place)
      }
    }

    public func setCurrentPlaceError(_ error: Swift.Error) {
      lock.withLock {
        placeResult = .failure(error)
      }
    }

    public func setIsRequestingLocation(_ value: Bool) {
      lock.withLock {
        isRequestingLocationValue = value
      }
    }

    @MainActor
    override public func requestWhenInUseAuthorization() async -> AuthorizationStatus {
      lock.withLock {
        requestWhenInUseAuthorizationCallCountValue += 1
        if storedAuthorizationStatus == .notDetermined {
          storedAuthorizationStatus = .authorizedWhenInUse
        }
        return storedAuthorizationStatus
      }
    }

    @MainActor
    override public func currentLocation(options: RequestOptions = RequestOptions()) async throws -> CLLocation {
      let result = lock.withLock {
        recordedCurrentLocationCalls.append(CurrentLocationCall(options: options))
        if let locationResult {
          return locationResult
        }
        if let storedLocation {
          return .success(storedLocation)
        }
        return .failure(TestError.unhandledCurrentLocation)
      }

      return try result.get()
    }

    @MainActor
    override public func currentPlace(options: RequestOptions = RequestOptions()) async throws -> Place {
      let result = lock.withLock {
        recordedCurrentPlaceCalls.append(CurrentPlaceCall(options: options))
        if let placeResult {
          return placeResult
        }
        if let storedPlacemark {
          do {
            return .success(try storedPlacemark.place)
          } catch {
            return .failure(error)
          }
        }
        return .failure(TestError.unhandledCurrentPlace)
      }

      return try result.get()
    }

    @MainActor
    override public func reverseGeocode(_ location: CLLocation) async throws -> Placemark {
      let result = lock.withLock {
        recordedReverseGeocodeCalls.append(ReverseGeocodeCall(location: location))
        if let reverseGeocodeResult {
          return reverseGeocodeResult
        }
        if let storedPlacemark {
          return .success(storedPlacemark)
        }
        return .failure(TestError.unhandledReverseGeocode)
      }

      return try result.get()
    }

    @MainActor
    override public func authorizationUpdates() -> AsyncStream<AuthorizationStatus> {
      AsyncStream { continuation in
        let id = UUID()
        let status = lock.withLock {
          authorizationStreamContinuations[id] = continuation
          return storedAuthorizationStatus
        }
        continuation.yield(status)
        continuation.onTermination = { [weak self] _ in
          Task { @MainActor in
            self?.lock.withLock {
              self?.authorizationStreamContinuations[id] = nil
            }
          }
        }
      }
    }

    @MainActor
    override public func locationUpdates() -> AsyncStream<CLLocation> {
      AsyncStream { continuation in
        let id = UUID()
        let location = lock.withLock {
          locationStreamContinuations[id] = continuation
          return storedLocation
        }
        if let location {
          continuation.yield(location)
        }
        continuation.onTermination = { [weak self] _ in
          Task { @MainActor in
            self?.lock.withLock {
              self?.locationStreamContinuations[id] = nil
            }
          }
        }
      }
    }
  }
}
