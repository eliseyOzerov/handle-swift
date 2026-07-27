import CoreLocation
import Foundation
import Mockable

/// Async CoreLocation handle for permissions, one-shot location requests, streams, and geocoding.
@MainActor
public class LocationHandle: @unchecked Sendable {
  public static let shared = LocationHandle()

  private let session: LocationSession
  private let geocoder: any Geocoder.Interface

  public init(geocoder: any Geocoder.Interface = Geocoder.shared) {
    session = LocationSession()
    self.geocoder = geocoder
  }

  @MainActor
  open var authorizationStatus: AuthorizationStatus {
    session.authorizationStatus
  }

  @MainActor
  open var latestLocation: CLLocation? {
    session.latestLocation
  }

  @MainActor
  open var isRequestingLocation: Bool {
    session.isRequestingLocation
  }

  @MainActor
  open func requestWhenInUseAuthorization() async -> AuthorizationStatus {
    await session.requestWhenInUseAuthorization()
  }

  @MainActor
  open func currentLocation(options: RequestOptions = RequestOptions()) async throws -> CLLocation {
    try await session.currentLocation(options: options)
  }

  @MainActor
  open func currentPlace(options: RequestOptions = RequestOptions()) async throws -> Place {
    let location = try await currentLocation(options: options)
    return try await reverseGeocode(location).place
  }

  @MainActor
  open func reverseGeocode(_ location: CLLocation) async throws -> Placemark {
    try await geocoder.reverseGeocode(location)
  }

  @MainActor
  open func authorizationUpdates() -> AsyncStream<AuthorizationStatus> {
    session.authorizationUpdates()
  }

  @MainActor
  open func locationUpdates() -> AsyncStream<CLLocation> {
    session.locationUpdates()
  }
}

extension LocationHandle {
  @Mockable
  public protocol Interface: Sendable {
    @MainActor
    var authorizationStatus: AuthorizationStatus { get }

    @MainActor
    var latestLocation: CLLocation? { get }

    @MainActor
    var isRequestingLocation: Bool { get }

    @MainActor
    func requestWhenInUseAuthorization() async -> AuthorizationStatus

    @MainActor
    func currentLocation(options: RequestOptions) async throws -> CLLocation

    @MainActor
    func currentPlace(options: RequestOptions) async throws -> Place

    @MainActor
    func reverseGeocode(_ location: CLLocation) async throws -> Placemark

    @MainActor
    func authorizationUpdates() -> AsyncStream<AuthorizationStatus>

    @MainActor
    func locationUpdates() -> AsyncStream<CLLocation>
  }

  #if MOCKING
  public typealias Mock = MockInterface
  #endif

  public enum AuthorizationStatus: Sendable, Equatable {
    case notDetermined
    case restricted
    case denied
    case authorizedWhenInUse
    case authorizedAlways
    case unknown(Int32)

    public var isAuthorized: Bool {
      self == .authorizedWhenInUse || self == .authorizedAlways
    }

    public var shouldRequestPermission: Bool {
      self == .notDetermined
    }

    init(_ status: CLAuthorizationStatus) {
      switch status {
      case .notDetermined: self = .notDetermined
      case .restricted: self = .restricted
      case .denied: self = .denied
      case .authorizedWhenInUse: self = .authorizedWhenInUse
      case .authorizedAlways: self = .authorizedAlways
      @unknown default: self = .unknown(status.rawValue)
      }
    }
  }

  public struct RequestOptions: Sendable, Equatable {
    public var desiredAccuracy: CLLocationAccuracy
    public var allowsCachedLocation: Bool
    public var requestsPermissionIfNeeded: Bool

    public init(
      desiredAccuracy: CLLocationAccuracy = kCLLocationAccuracyBest,
      allowsCachedLocation: Bool = true,
      requestsPermissionIfNeeded: Bool = true
    ) {
      self.desiredAccuracy = desiredAccuracy
      self.allowsCachedLocation = allowsCachedLocation
      self.requestsPermissionIfNeeded = requestsPermissionIfNeeded
    }
  }

  public enum Error: Swift.Error, Sendable, Equatable {
    case authorizationNotDetermined
    case authorizationDenied(AuthorizationStatus)
    case locationUnavailable
    case placeUnavailable
  }

  public struct Coordinate: Sendable, Equatable {
    public var latitude: Double
    public var longitude: Double

    public init(latitude: Double, longitude: Double) {
      self.latitude = latitude
      self.longitude = longitude
    }

    init(_ coordinate: CLLocationCoordinate2D) {
      latitude = coordinate.latitude
      longitude = coordinate.longitude
    }
  }

  public struct Placemark: Sendable, Equatable {
    public var name: String?
    public var locality: String?
    public var administrativeArea: String?
    public var country: String?
    public var isoCountryCode: String?
    public var coordinate: Coordinate?

    public init(
      name: String? = nil,
      locality: String? = nil,
      administrativeArea: String? = nil,
      country: String? = nil,
      isoCountryCode: String? = nil,
      coordinate: Coordinate? = nil
    ) {
      self.name = name
      self.locality = locality
      self.administrativeArea = administrativeArea
      self.country = country
      self.isoCountryCode = isoCountryCode
      self.coordinate = coordinate
    }

    init(_ placemark: CLPlacemark) {
      name = placemark.name
      locality = placemark.locality
      administrativeArea = placemark.administrativeArea
      country = placemark.country
      isoCountryCode = placemark.isoCountryCode
      coordinate = placemark.location.map { Coordinate($0.coordinate) }
    }

    public var place: Place {
      get throws {
        let city = normalized(locality ?? administrativeArea)
        let country = normalized(country)
        guard let city, let country else {
          throw Error.placeUnavailable
        }
        return Place(city: city, country: country, placemark: self)
      }
    }

    private func normalized(_ value: String?) -> String? {
      let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      return trimmed.isEmpty ? nil : trimmed
    }
  }

  public struct Place: Sendable, Equatable {
    public var city: String
    public var country: String
    public var placemark: Placemark

    public init(city: String, country: String, placemark: Placemark) {
      self.city = city
      self.country = country
      self.placemark = placemark
    }
  }
}

extension LocationHandle: LocationHandle.Interface {}

public extension LocationHandle.Interface {
  @MainActor
  func currentLocation(options: LocationHandle.RequestOptions = LocationHandle.RequestOptions()) async throws -> CLLocation {
    try await currentLocation(options: options)
  }

  @MainActor
  func currentPlace(options: LocationHandle.RequestOptions = LocationHandle.RequestOptions()) async throws -> LocationHandle.Place {
    try await currentPlace(options: options)
  }
}

@MainActor
private final class LocationSession: NSObject, @preconcurrency CLLocationManagerDelegate {
  private let manager = CLLocationManager()
  private var authorizationContinuation: CheckedContinuation<LocationHandle.AuthorizationStatus, Never>?
  private var locationContinuations: [CheckedContinuation<CLLocation, Swift.Error>] = []
  private var authorizationStreamContinuations: [UUID: AsyncStream<LocationHandle.AuthorizationStatus>.Continuation] = [:]
  private var locationStreamContinuations: [UUID: AsyncStream<CLLocation>.Continuation] = [:]

  var latestLocation: CLLocation?
  var isRequestingLocation = false

  override init() {
    super.init()
    manager.delegate = self
    manager.desiredAccuracy = kCLLocationAccuracyBest
  }

  var authorizationStatus: LocationHandle.AuthorizationStatus {
    LocationHandle.AuthorizationStatus(manager.authorizationStatus)
  }

  func requestWhenInUseAuthorization() async -> LocationHandle.AuthorizationStatus {
    guard authorizationStatus == .notDetermined else {
      return authorizationStatus
    }

    return await withCheckedContinuation { continuation in
      authorizationContinuation = continuation
      manager.requestWhenInUseAuthorization()
    }
  }

  func currentLocation(options: LocationHandle.RequestOptions) async throws -> CLLocation {
    manager.desiredAccuracy = options.desiredAccuracy

    if options.allowsCachedLocation, let latestLocation {
      return latestLocation
    }

    var status = authorizationStatus
    if status == .notDetermined {
      guard options.requestsPermissionIfNeeded else {
        throw LocationHandle.Error.authorizationNotDetermined
      }
      status = await requestWhenInUseAuthorization()
    }

    guard status.isAuthorized else {
      throw LocationHandle.Error.authorizationDenied(status)
    }

    return try await withCheckedThrowingContinuation { continuation in
      locationContinuations.append(continuation)
      isRequestingLocation = true
      manager.requestLocation()
    }
  }

  func authorizationUpdates() -> AsyncStream<LocationHandle.AuthorizationStatus> {
    AsyncStream { continuation in
      let id = UUID()
      authorizationStreamContinuations[id] = continuation
      continuation.yield(authorizationStatus)
      continuation.onTermination = { [weak self] _ in
        Task { @MainActor in
          self?.authorizationStreamContinuations[id] = nil
        }
      }
    }
  }

  func locationUpdates() -> AsyncStream<CLLocation> {
    AsyncStream { continuation in
      let id = UUID()
      locationStreamContinuations[id] = continuation
      if let latestLocation {
        continuation.yield(latestLocation)
      }
      continuation.onTermination = { [weak self] _ in
        Task { @MainActor in
          self?.locationStreamContinuations[id] = nil
        }
      }
    }
  }

  func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
    let status = authorizationStatus
    authorizationContinuation?.resume(returning: status)
    authorizationContinuation = nil
    for continuation in authorizationStreamContinuations.values {
      continuation.yield(status)
    }
  }

  func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
    guard let location = locations.last else {
      finishLocationRequests(.failure(LocationHandle.Error.locationUnavailable))
      return
    }

    latestLocation = location
    isRequestingLocation = false
    for continuation in locationStreamContinuations.values {
      continuation.yield(location)
    }
    finishLocationRequests(.success(location))
  }

  func locationManager(_ manager: CLLocationManager, didFailWithError error: Swift.Error) {
    isRequestingLocation = false
    finishLocationRequests(.failure(error))
  }

  private func finishLocationRequests(_ result: Result<CLLocation, Swift.Error>) {
    let continuations = locationContinuations
    locationContinuations.removeAll()
    for continuation in continuations {
      switch result {
      case .success(let location):
        continuation.resume(returning: location)
      case .failure(let error):
        continuation.resume(throwing: error)
      }
    }
  }
}
