/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Removing a device from the sync device list. It cannot revoke anything
 * (every device holds the recovery phrase), but a removed device must stay
 * off the list when its next sync message arrives.
 */

import { setupVault, vaultReady } from './helpers/harness';

// An ES module Jest does not transform; the device list never signs anything.
jest.mock('@noble/secp256k1', () => ({ schnorr: {} }));

const vault = setupVault('https://example.com/');
const CHAIN_ID = 'c'.repeat(32);

const device = (id: string, name: string, isThisDevice = false) => ({
  id,
  name,
  deviceType: 'Desktop',
  publicKey: '',
  createdAt: 1,
  lastSeen: 1,
  isThisDevice,
});

const seed = {
  sync_config: {
    enabled: true,
    chainId: CHAIN_ID,
    deviceId: 'laptop',
    deviceName: 'Laptop',
    seedHash: 'a'.repeat(64),
  },
  sync_devices: {
    id: CHAIN_ID,
    createdAt: 1,
    devices: [device('laptop', 'Laptop', true), device('phone', 'Old phone')],
  },
};

/** The real sync service, recording a message as it does for each one it reads. */
function syncServiceOnLaptop() {
  const { SyncService } = jest.requireActual('../src/sync/sync-service');
  const service = new SyncService();
  Object.assign(service, { deviceId: 'laptop', log() {} });
  return (deviceId: string, timestamp = 2) =>
    service.updateRemoteDevice({
      type: 'announce',
      chainId: CHAIN_ID,
      deviceId,
      deviceName: deviceId,
      deviceType: 'Mobile',
      timestamp,
      payload: { action: 'online' },
    });
}

const listed = async () =>
  ((await vault.send({ type: 'GET_SYNC_CHAIN_INFO' })).chainInfo.devices as { id: string }[]).map(
    (d) => d.id
  );

beforeAll(() => vaultReady(vault));
beforeEach(() => vault.reset(seed));

describe('removing a sync device', () => {
  it('takes it off the list', async () => {
    expect(await vault.send({ type: 'REMOVE_SYNC_DEVICE', deviceId: 'phone' })).toEqual({
      success: true,
    });

    expect(await listed()).toEqual(['laptop']);
  });

  it('keeps it off the list when its next message arrives', async () => {
    const seen = syncServiceOnLaptop();
    await vault.send({ type: 'REMOVE_SYNC_DEVICE', deviceId: 'phone' });

    await seen('phone', 5);
    await seen('tablet', 6);

    expect(await listed()).toEqual(['laptop', 'tablet']);
  });

  it('cannot remove this device, which leaves the chain instead', async () => {
    const response = await vault.send({ type: 'REMOVE_SYNC_DEVICE', deviceId: 'laptop' });

    expect(response.success).toBe(false);
    expect(await listed()).toEqual(['laptop', 'phone']);
  });

  it('is forgotten with the chain', async () => {
    await vault.send({ type: 'REMOVE_SYNC_DEVICE', deviceId: 'phone' });
    await vault.send({ type: 'LEAVE_SYNC_CHAIN' });

    expect(vault.storage.sync_devices).toBeNull();
  });

  it('is not undone by a message read before the removal was saved', async () => {
    // Both run in the worker, one module instance; the list is rewritten by
    // whichever finishes last unless the two are serialized.
    const devices = jest.requireActual('../src/sync/devices');
    const sighting = devices.recordDeviceSighting(
      { deviceId: 'phone', deviceName: 'Old phone', timestamp: 9 },
      'laptop'
    );
    const removal = devices.removeDevice('phone', 'laptop');

    expect(await Promise.all([sighting, removal])).toEqual(['seen', 'removed']);
    expect(await listed()).toEqual(['laptop']);
  });
});
