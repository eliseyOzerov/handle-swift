import Foundation

/// A single test handle that can stub Keychain behavior, record calls, and store values in memory.
public final class TestKeychainHandle: KeychainHandling, @unchecked Sendable {
  public struct SetDataCall: Equatable, Sendable {
    public var data: Data
    public var key: KeychainKey

    public init(data: Data, key: KeychainKey) {
      self.data = data
      self.key = key
    }
  }

  public struct DataCall: Equatable, Sendable {
    public var key: KeychainKey

    public init(key: KeychainKey) {
      self.key = key
    }
  }

  public struct DeleteCall: Equatable, Sendable {
    public var key: KeychainKey

    public init(key: KeychainKey) {
      self.key = key
    }
  }

  public var setDataHandler: (@Sendable (Data, KeychainKey) throws -> Void)?
  public var dataHandler: (@Sendable (KeychainKey) throws -> Data?)?
  public var deleteHandler: (@Sendable (KeychainKey) throws -> Void)?

  private let lock = NSLock()
  private var storage: [KeychainKey: Data]
  private var recordedSetDataCalls: [SetDataCall] = []
  private var recordedDataCalls: [DataCall] = []
  private var recordedDeleteCalls: [DeleteCall] = []

  public init(storage: [KeychainKey: Data] = [:]) {
    self.storage = storage
  }

  public var setDataCalls: [SetDataCall] {
    withLock { recordedSetDataCalls }
  }

  public var dataCalls: [DataCall] {
    withLock { recordedDataCalls }
  }

  public var deleteCalls: [DeleteCall] {
    withLock { recordedDeleteCalls }
  }

  public var setDataCallCount: Int {
    setDataCalls.count
  }

  public var dataCallCount: Int {
    dataCalls.count
  }

  public var deleteCallCount: Int {
    deleteCalls.count
  }

  public func set(_ data: Data, for key: KeychainKey) throws {
    withLock {
      recordedSetDataCalls.append(SetDataCall(data: data, key: key))
    }

    if let setDataHandler {
      try setDataHandler(data, key)
      return
    }

    withLock {
      storage[key] = data
    }
  }

  public func data(for key: KeychainKey) throws -> Data? {
    withLock {
      recordedDataCalls.append(DataCall(key: key))
    }

    if let dataHandler {
      return try dataHandler(key)
    }

    return withLock {
      storage[key]
    }
  }

  public func delete(_ key: KeychainKey) throws {
    withLock {
      recordedDeleteCalls.append(DeleteCall(key: key))
    }

    if let deleteHandler {
      try deleteHandler(key)
      return
    }

    withLock {
      _ = storage.removeValue(forKey: key)
    }
  }

  public func removeAll() {
    withLock {
      storage.removeAll()
      recordedSetDataCalls.removeAll()
      recordedDataCalls.removeAll()
      recordedDeleteCalls.removeAll()
    }
  }

  private func withLock<T>(_ body: () throws -> T) rethrows -> T {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }
}
