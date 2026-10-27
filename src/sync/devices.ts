// The list of devices in this device's sync chain, as shown on the sync
// settings page (chrome.storage.local['sync_devices']).
//
// The list is local bookkeeping, not access control. Every device in a
// chain derives the same keys from the recovery phrase, so removing a device
// here cannot stop it reading or changing the vault through sync; only a new
// chain, joined by the devices the user keeps, does that. Removing a device
// hides it, and remembers its ID so its next message does not list it again.

import type { SyncDevice } from '../types';

export const SYNC_DEVICES_KEY = 'sync_devices';

export interface SyncDeviceList {
  id: string;
  createdAt: number;
  devices: SyncDevice[];
  /** Devices the user removed from this list; never listed again. */
  removedDeviceIds?: string[];
  [field: string]: unknown;
}

/** What another device's sync message says about it. */
export interface DeviceSighting {
  deviceId: string;
  deviceName?: string;
  deviceType?: string;
  timestamp: number;
}

export type RemoveResult = 'removed' | 'this-device' | 'no-chain';

// The background and the sync service both rewrite the list; one queue keeps
// a removal from being undone by a sighting that read the list before it.
let queue: Promise<unknown> = Promise.resolve();

function update<T>(change: (list: SyncDeviceList | null) => Promise<T> | T): Promise<T> {
  const result = queue.then(async () => {
    const stored = (await chrome.storage.local.get(SYNC_DEVICES_KEY))[SYNC_DEVICES_KEY];
    return change(stored && Array.isArray(stored.devices) ? (stored as SyncDeviceList) : null);
  });
  queue = result.catch(() => undefined);
  return result;
}

async function save(list: SyncDeviceList): Promise<void> {
  await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: list });
}

/**
 * Add or refresh the device a sync message came from. Returns 'new' when it
 * was not listed before, 'seen' when it was, and 'ignored' for this device,
 * a removed device, or when there is no chain.
 */
export function recordDeviceSighting(
  sighting: DeviceSighting,
  thisDeviceId: string | null
): Promise<'new' | 'seen' | 'ignored'> {
  return update(async (list) => {
    if (!list || !sighting.deviceId) return 'ignored';
    if (list.removedDeviceIds?.includes(sighting.deviceId)) return 'ignored';

    const index = list.devices.findIndex((device) => device.id === sighting.deviceId);
    const isThisDevice = sighting.deviceId === thisDeviceId;
    const device: SyncDevice = {
      id: sighting.deviceId,
      name: sighting.deviceName || `Device ${sighting.deviceId.substring(0, 8)}`,
      deviceType: sighting.deviceType || 'Desktop',
      publicKey: '',
      createdAt: index >= 0 ? list.devices[index].createdAt : sighting.timestamp,
      lastSeen: sighting.timestamp,
      isThisDevice,
    };
    if (index >= 0) {
      list.devices[index] = { ...list.devices[index], ...device };
      await save(list);
      return 'seen';
    }
    if (isThisDevice) return 'ignored';
    list.devices.push(device);
    await save(list);
    return 'new';
  });
}

/**
 * Take a device off the list and remember not to list it again. This device
 * cannot be removed; leaving the chain is how it goes.
 */
export function removeDevice(deviceId: string, thisDeviceId: string | null): Promise<RemoveResult> {
  return update(async (list) => {
    if (!list) return 'no-chain';
    if (deviceId === thisDeviceId) return 'this-device';
    const removed = new Set(list.removedDeviceIds ?? []);
    removed.add(deviceId);
    await save({
      ...list,
      devices: list.devices.filter((device) => device.id !== deviceId),
      removedDeviceIds: [...removed],
    });
    return 'removed';
  });
}
